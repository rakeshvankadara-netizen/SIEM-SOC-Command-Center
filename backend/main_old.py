from fastapi import FastAPI, WebSocket, HTTPException
from threat_intelligence import check_ip_reputation
from ueba_detection import detect_anomalous_behavior
from ueba_baseline import (
    calculate_behavior_baseline,
    load_behavior_baseline,
    save_behavior_baseline
)
from fastapi.middleware.cors import CORSMiddleware
from elasticsearch import Elasticsearch
import asyncio
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json


app = FastAPI(title="SIEM Backend")


# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# ELASTICSEARCH CONNECTION
# --------------------------------------------------

es = Elasticsearch("http://127.0.0.1:9200")


# --------------------------------------------------
# RISK SCORING ENGINE
# --------------------------------------------------

def calculate_severity(risk_score):

    if risk_score >= 80:
        return "CRITICAL"

    elif risk_score >= 60:
        return "HIGH"

    elif risk_score >= 30:
        return "MEDIUM"

    else:
        return "LOW"


# --------------------------------------------------
# EVENT NORMALIZATION
# --------------------------------------------------

def normalize_event(event):
    """Return a copy with common Windows and nested fields normalized.

    Keeps the original fields intact so existing API responses and detection
    modules continue to work, while adding canonical fields used by detectors.
    """
    normalized = dict(event or {})
    event_details = normalized.get("event") or {}
    winlog = normalized.get("winlog") or {}
    event_data = winlog.get("event_data") or {}

    code = str(
        event_details.get("code")
        or winlog.get("event_id")
        or normalized.get("event_id")
        or ""
    )
    current_type = normalized.get("event_type", [])
    types = (
        {str(item).strip().lower() for item in current_type}
        if isinstance(current_type, list)
        else {str(current_type).strip().lower()}
    )
    types.discard("")

    # Map Windows Security logon events to the names used by detections.
    if code == "4625":
        normalized["event_type"] = "login_failed"
    elif code == "4624":
        normalized["event_type"] = "login_success"
    elif code == "4672":
        normalized["event_type"] = "privilege_escalation"
    elif "login_failed" in types:
        normalized["event_type"] = "login_failed"
    elif "login_success" in types:
        normalized["event_type"] = "login_success"

    source_ip = (
        normalized.get("source_ip")
        or (normalized.get("source") or {}).get("ip")
        or event_data.get("IpAddress")
        or event_data.get("IpAddressV6")
    )
    if isinstance(source_ip, list):
        source_ip = next((item for item in source_ip if item), None)
    if isinstance(source_ip, str):
        source_ip = source_ip.strip()
        if source_ip in ("", "-", "::", "0.0.0.0"):
            source_ip = None
    if source_ip:
        normalized["source_ip"] = source_ip


    # Normalize Windows/ECS username fields for UEBA. Windows 4625 events
    # often have TargetUserName="-" but a useful SubjectUserName value.
    user_details = normalized.get("user") or {}
    username_candidates = (
        normalized.get("username"),
        user_details.get("name"),
        event_data.get("TargetUserName"),
        event_data.get("SubjectUserName"),
        event_data.get("AccountName"),
    )
    username = next(
        (str(value).strip() for value in username_candidates
         if value is not None and str(value).strip() not in ("", "-")),
        None
    )
    if username and username.upper() not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        normalized["username"] = username
    else:
        normalized.pop("username", None)

    destination_port = (
        normalized.get("destination_port")
        or (normalized.get("destination") or {}).get("port")
        or event_data.get("DestinationPort")
    )
    if destination_port is not None:
        normalized["destination_port"] = destination_port

    return normalized


def get_login_entity(event):
    """Stable key for failed-login correlation when Windows has no source IP."""
    event = normalize_event(event)
    winlog = event.get("winlog") or {}
    data = winlog.get("event_data") or {}
    source_ip = event.get("source_ip") or (event.get("source") or {}).get("ip")
    if isinstance(source_ip, list):
        source_ip = next((str(x).strip() for x in source_ip if x), None)
    if isinstance(source_ip, str):
        source_ip = source_ip.strip()
        if source_ip and source_ip not in ("-", "::", "0.0.0.0", "::1"):
            return ("ip", source_ip)
    # Windows 4625 often reports IpAddress='-' for local process logons.
    username = str(data.get("TargetUserName") or data.get("SubjectUserName") or "").strip()
    process = str(data.get("ProcessName") or "").strip().lower()
    host = str((event.get("host") or {}).get("name") or winlog.get("computer_name") or "unknown-host").strip().lower()
    if username and username != "-":
        return ("user", host, username.lower())
    if process:
        return ("process", host, process)
    return ("host", host)


# --------------------------------------------------
# PORT SCAN DETECTION
# --------------------------------------------------

def detect_port_scan(events, threshold=5):
    """Detect a source IP contacting 5+ unique destination ports."""
    port_data = {}

    for event in events:
        source_ip = event.get("source_ip")
        destination_port = event.get("destination_port")

        if not source_ip or destination_port is None:
            continue

        if source_ip not in port_data:
            port_data[source_ip] = set()

        port_data[source_ip].add(str(destination_port))

    return {
        source_ip: ports
        for source_ip, ports in port_data.items()
        if len(ports) >= threshold
    }


# --------------------------------------------------
# SUSPICIOUS DNS ACTIVITY DETECTION
# --------------------------------------------------

def detect_dns_activity(events, threshold=20):
    """Detect a source IP making 20+ DNS queries within the analysis window."""
    dns_counts = Counter()

    for event in events:
        if event.get("event_type") != "dns_query":
            continue

        source_ip = event.get("source_ip")

        if source_ip:
            dns_counts[source_ip] += 1

    return {
        source_ip: count
        for source_ip, count in dns_counts.items()
        if count >= threshold
    }


# --------------------------------------------------
# SUSPICIOUS HTTP ACTIVITY DETECTION
# --------------------------------------------------

def detect_http_activity(events, threshold=20):
    """Detect a source IP making 20+ HTTP requests within the analysis window."""
    http_counts = Counter()

    for event in events:
        if event.get("event_type") != "http_request":
            continue

        source_ip = event.get("source_ip")

        if source_ip:
            http_counts[source_ip] += 1

    return {
        source_ip: count
        for source_ip, count in http_counts.items()
        if count >= threshold
    }


# --------------------------------------------------
# SUSPICIOUS SSH ACTIVITY DETECTION
# --------------------------------------------------

def detect_ssh_activity(events, threshold=20):
    """Detect a source IP making 20+ SSH connection attempts within the analysis window."""
    ssh_counts = Counter()
    file_access_counts = Counter()

    for event in events:
        if event.get("event_type") != "ssh_connection":
            continue

        source_ip = event.get("source_ip")

        if source_ip:
            ssh_counts[source_ip] += 1

    return {
        source_ip: count
        for source_ip, count in ssh_counts.items()
        if count >= threshold
    }


# --------------------------------------------------
# SUSPICIOUS FILE ACCESS DETECTION
# --------------------------------------------------

def detect_file_access(events, threshold=20):
    """Detect a source IP making 20+ file access events within the analysis window."""
    file_counts = Counter()

    for event in events:
        if event.get("event_type") != "file_access":
            continue

        source_ip = event.get("source_ip")

        if source_ip:
            file_counts[source_ip] += 1

    return {
        source_ip: count
        for source_ip, count in file_counts.items()
        if count >= threshold
    }


# --------------------------------------------------
# SUSPICIOUS PROCESS EXECUTION DETECTION
# --------------------------------------------------

def detect_process_execution(events, threshold=20):
    """Detect a source IP making 20+ process execution events within the analysis window."""
    process_counts = Counter()

    for event in events:
        if event.get("event_type") != "process_execution":
            continue

        source_ip = event.get("source_ip")

        if source_ip:
            process_counts[source_ip] += 1

    return {
        source_ip: count
        for source_ip, count in process_counts.items()
        if count >= threshold
    }


# --------------------------------------------------
# SUSPICIOUS PRIVILEGE ESCALATION DETECTION
# --------------------------------------------------

def detect_privilege_escalation(events):
    """Detect privilege escalation events such as sudo/root elevation."""
    return {
        event.get("source_ip"): sum(
            1 for item in events
            if item.get("event_type") == "privilege_escalation"
            and item.get("source_ip") == event.get("source_ip")
        )
        for event in events
        if event.get("event_type") == "privilege_escalation"
        and event.get("source_ip")
    }


# --------------------------------------------------
# SUSPICIOUS COMMAND EXECUTION DETECTION
# --------------------------------------------------

def detect_command_execution(events, threshold=20):
    """Detect a source IP making 20+ command execution events within the analysis window."""
    command_counts = Counter()

    for event in events:
        if event.get("event_type") != "command_execution":
            continue

        source_ip = event.get("source_ip")

        if source_ip:
            command_counts[source_ip] += 1

    return {
        source_ip: count
        for source_ip, count in command_counts.items()
        if count >= threshold
    }


# --------------------------------------------------
# MULTI-STAGE ATTACK CHAIN DETECTION
# --------------------------------------------------

def detect_attack_chain(events):
    """
    Detect a multi-stage attack chain from the same source IP:
    Port Scan -> Brute Force -> Successful Login -> Privilege Escalation
    """
    failed_counts = Counter()
    successful_ips = set()
    port_data = {}
    privilege_ips = set()

    for event in events:
        source_ip = event.get("source_ip")
        if not source_ip:
            continue

        event_type = event.get("event_type")

        if event_type == "login_failed":
            failed_counts[source_ip] += 1

        elif event_type == "login_success":
            successful_ips.add(source_ip)

        elif event_type == "privilege_escalation":
            privilege_ips.add(source_ip)

        if event.get("destination_port") is not None:
            if source_ip not in port_data:
                port_data[source_ip] = set()
            port_data[source_ip].add(str(event.get("destination_port")))

    attack_chain_ips = set()

    for source_ip in set(failed_counts) | successful_ips | privilege_ips | set(port_data):
        has_port_scan = len(port_data.get(source_ip, set())) >= 5
        has_brute_force = failed_counts.get(source_ip, 0) >= 5
        has_success = source_ip in successful_ips
        has_privilege_escalation = source_ip in privilege_ips

        if (
            has_port_scan
            and has_brute_force
            and has_success
            and has_privilege_escalation
        ):
            attack_chain_ips.add(source_ip)

    return attack_chain_ips


# --------------------------------------------------
# ROOT
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "message": "SIEM Backend is running"
    }


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/health")
def health():

    try:

        info = es.info()

        return {
            "elasticsearch": True,
            "version": info["version"]["number"]
        }

    except Exception as e:

        return {
            "elasticsearch": False,
            "error": str(e)
        }


# --------------------------------------------------
# GET SECURITY EVENTS
# --------------------------------------------------

@app.get("/events")
def get_events(limit: int = 100, event_id: int = None):

    # Keep the requested limit within a safe range.
    limit = max(1, min(limit, 500))

    # Filter by Windows Event ID when requested.
    if event_id is not None:
        query = {
            "term": {
                "winlog.event_id": event_id
            }
        }
    else:
        query = {
            "match_all": {}
        }

    response = es.search(
        index="siem-events-*",
        query=query,
        size=limit,
        sort=[
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]
    )

    events = []

    for hit in response["hits"]["hits"]:

        event = hit["_source"].copy()

        event["id"] = hit["_id"]

        events.append(event)

    return {
        "total": response["hits"]["total"]["value"],
        "limit": limit,
        "event_id": event_id,
        "events": events
    }


# --------------------------------------------------
# MONITORED HOSTS
# --------------------------------------------------

@app.get("/hosts")
def get_hosts():
    """
    Return monitored hosts with threat status calculated from the
    alerts produced by this SIEM's existing detection engine.

    NORMAL   = no current alert for the host
    WARNING  = medium-severity alert
    CRITICAL = high/critical-severity alert
    """
    response = es.search(
        index="siem-events-*",
        query={"match_all": {}},
        size=0,
        aggs={
            "hosts": {
                "terms": {
                    "field": "host.hostname.keyword",
                    "size": 50
                }
            }
        }
    )

    # Start with the real host/event counts from Elasticsearch.
    hosts_by_name = {}
    for bucket in response["aggregations"]["hosts"]["buckets"]:
        hostname = bucket["key"]
        hosts_by_name[hostname] = {
            "hostname": hostname,
            "event_count": bucket["doc_count"],
            "threat_count": 0,
            "risk_score": 0,
            "severity": "LOW",
            "status": "NORMAL"
        }

    # Reuse the existing SIEM alert engine rather than inventing
    # threat labels or treating every event as malicious.
    try:
        alert_result = get_alerts()
        alerts = alert_result.get("alerts", [])
    except Exception as exc:
        print("Host threat-status enrichment error:", repr(exc))
        alerts = []

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    for alert in alerts:
        host_info = alert.get("host") or {}
        winlog_info = alert.get("winlog") or {}
        hostname = (
            host_info.get("hostname")
            or host_info.get("name")
            or winlog_info.get("computer_name")
        )

        if not hostname or hostname not in hosts_by_name:
            continue

        host = hosts_by_name[hostname]
        host["threat_count"] += 1

        try:
            risk_score = int(alert.get("risk_score") or 0)
        except (TypeError, ValueError):
            risk_score = 0

        severity = str(alert.get("severity") or "LOW").upper()

        if risk_score > host["risk_score"]:
            host["risk_score"] = risk_score

        if severity_rank.get(severity, 0) > severity_rank.get(host["severity"], 0):
            host["severity"] = severity

    for host in hosts_by_name.values():
        if host["severity"] in ("HIGH", "CRITICAL"):
            host["status"] = "CRITICAL"
        elif host["severity"] == "MEDIUM":
            host["status"] = "WARNING"
        else:
            host["status"] = "NORMAL"

    hosts = sorted(
        hosts_by_name.values(),
        key=lambda item: item["event_count"],
        reverse=True
    )

    return {
        "total_hosts": len(hosts),
        "hosts": hosts
    }


# --------------------------------------------------
# SAFE SIMULATED EVENT GENERATOR (FOR TESTING ONLY)
# --------------------------------------------------

@app.post("/test/brute-force")
def create_brute_force_test_events():
    """Insert five clearly labelled synthetic failed-login events.

    Uses the documentation-only TEST-NET IP 198.51.100.25. These events are
    simulations, not real login attempts or evidence of an actual attack.
    """
    now = datetime.now(timezone.utc)
    index_name = f"siem-events-{now.strftime('%Y.%m.%d')}"
    test_ip = "198.51.100.25"
    test_user = "siem_test_user"
    inserted_ids = []

    for attempt in range(5):
        timestamp = now.isoformat()
        document = {
            "@timestamp": timestamp,
            "event_type": ["windows_security_event", "login_failed"],
            "event": {
                "code": "4625",
                "action": "Logon",
                "outcome": "failure",
                "kind": "event"
            },
            "winlog": {
                "event_id": "4625",
                "channel": "Security",
                "computer_name": "SIEM-TEST-HOST",
                "event_data": {
                    "TargetUserName": test_user,
                    "SubjectUserName": test_user,
                    "IpAddress": test_ip,
                    "ProcessName": "SIEM-Simulation"
                }
            },
            "username": test_user,
            "source_ip": test_ip,
            "message": f"SIMULATED failed login attempt {attempt + 1} of 5",
            "threat_type": "SIMULATION ONLY - Brute Force Test",
            "host": {
                "name": "siem-test-host",
                "hostname": "SIEM-TEST-HOST"
            },
            "tags": ["siem_simulation", "test_event"]
        }
        result = es.index(index=index_name, document=document, refresh=True)
        inserted_ids.append(result.get("_id"))

    return {
        "message": "Inserted five synthetic failed-login events.",
        "simulation_only": True,
        "index": index_name,
        "source_ip": test_ip,
        "username": test_user,
        "events_inserted": len(inserted_ids),
        "event_ids": inserted_ids,
        "next_step": "Call GET /alerts to verify the simulated brute-force alert."
    }


# --------------------------------------------------
# PERSISTENT SECURITY ALERT HISTORY
# --------------------------------------------------

ALERT_HISTORY_INDEX = "siem-alert-history"


def save_alert_history(alerts):
    """Persist alerts without creating a new record on every dashboard refresh.

    UEBA alerts are grouped by entity + anomaly type, because the detector
    evaluates a rolling five-minute window and otherwise creates a new record
    each time that window is refreshed. Event-based alerts retain event-level
    identity so separate incidents are not merged.
    """
    saved = 0
    now = datetime.now(timezone.utc).isoformat()

    for alert in alerts:
        host_info = alert.get("host") or {}
        if isinstance(host_info, str):
            host_name = host_info
        else:
            winlog_info = alert.get("winlog") or {}
            host_name = (
                host_info.get("hostname")
                or host_info.get("name")
                or winlog_info.get("computer_name")
                or "Unknown host"
            )

        alert_name = alert.get("alert", "Security Alert")
        threat_type = alert.get("threat_type", "")
        source_ip = alert.get("source_ip") or ""
        username = alert.get("username") or ""
        event_id = (
            alert.get("event_id")
            or (alert.get("event") or {}).get("code")
            or (alert.get("winlog") or {}).get("event_id")
            or ""
        )
        is_ueba = "UEBA" in str(alert_name).upper()

        # Rolling-window UEBA results represent the same active condition
        # across refreshes. Keep one history row per entity/condition.
        if is_ueba:
            entity_type = str(alert.get("entity_type") or "UNKNOWN").upper()
            entity_key = str(alert.get("entity_key") or "")
            # Keep user, IP, and user-IP relationship anomalies distinct.
            # Never treat a synthetic user key as a network source IP.
            if entity_type == "USER":
                entity_identity = {
                    "entity_type": entity_type,
                    "username": username or entity_key,
                }
            elif entity_type == "IP":
                entity_identity = {
                    "entity_type": entity_type,
                    "source_ip": source_ip or entity_key,
                }
            elif entity_type == "USER_IP_RELATIONSHIP":
                entity_identity = {
                    "entity_type": entity_type,
                    "username": username,
                    "source_ip": source_ip,
                }
            else:
                entity_identity = {
                    "entity_type": entity_type,
                    "username": username,
                    "source_ip": source_ip,
                    "entity_key": entity_key,
                }

            identity = {
                "kind": "ueba",
                "alert": alert_name,
                "threat_type": threat_type,
                "host": host_name,
                **entity_identity,
            }
        else:
            identity = {
                "kind": "event",
                "alert": alert_name,
                "event_timestamp": (
                    alert.get("@timestamp")
                    or alert.get("timestamp")
                    or now
                ),
                "host": host_name,
                "source_ip": source_ip,
                "username": username,
                "event_id": event_id,
                "threat_type": threat_type,
            }

        fingerprint = json.dumps(identity, sort_keys=True, default=str)
        history_id = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

        document = {
            "history_id": history_id,
            "alert": alert_name,
            "event_timestamp": str(
                alert.get("@timestamp") or alert.get("timestamp") or now
            ),
            "host": host_name,
            "source_ip": source_ip,
            "username": username,
            "event_id": str(event_id),
            "threat_type": threat_type,
            "severity": str(alert.get("severity", "LOW")).upper(),
            "risk_score": int(alert.get("risk_score") or 0),
            "message": alert.get("message", ""),
            "simulation_only": (
                "siem_simulation" in (alert.get("tags") or [])
                or "SIMULATION" in str(threat_type).upper()
            ),
            "last_seen": now,
        }

        es.update(
            index=ALERT_HISTORY_INDEX,
            id=history_id,
            scripted_upsert=True,
            script={
                "lang": "painless",
                "source": """
                    ctx._source.putAll(params.document);
                    if (ctx._source.status == null) {
                        ctx._source.status = 'OPEN';
                    }
                    if (ctx._source.first_seen == null) {
                        ctx._source.first_seen = params.now;
                    }
                """,
                "params": {"document": document, "now": now},
            },
            upsert={},
            retry_on_conflict=3,
        )
        saved += 1

    return saved


@app.get("/alert-history")
def get_alert_history(limit: int = 100, status: str = None):
    """Return persistent alerts, including alerts outside the live 5-minute window."""
    limit = max(1, min(limit, 500))

    filters = []
    if status:
        normalized_status = status.strip().upper()
        if normalized_status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
            raise HTTPException(
                status_code=400,
                detail="status must be OPEN, ACKNOWLEDGED, or RESOLVED"
            )
        filters.append({"term": {"status.keyword": normalized_status}})

    query = {"bool": {"filter": filters}} if filters else {"match_all": {}}

    try:
        response = es.search(
            index=ALERT_HISTORY_INDEX,
            query=query,
            size=limit,
            sort=[{"last_seen": {"order": "desc", "unmapped_type": "date"}}],
        )
    except Exception as exc:
        # An absent history index means no alerts have been persisted yet.
        if "index_not_found_exception" in str(exc):
            return {"total": 0, "alerts": []}
        raise

    records = []
    for hit in response["hits"]["hits"]:
        record = hit["_source"].copy()
        record["history_id"] = hit["_id"]
        records.append(record)

    total = response["hits"]["total"]
    total_value = total["value"] if isinstance(total, dict) else total
    return {"total": total_value, "alerts": records}


@app.patch("/alert-history/{alert_id}/status")
def update_alert_history_status(alert_id: str, status: str):
    """Acknowledge or resolve a persistent alert."""
    normalized_status = status.strip().upper()
    if normalized_status not in {"ACKNOWLEDGED", "RESOLVED", "OPEN"}:
        raise HTTPException(
            status_code=400,
            detail="status must be OPEN, ACKNOWLEDGED, or RESOLVED"
        )

    if not es.exists(index=ALERT_HISTORY_INDEX, id=alert_id):
        raise HTTPException(status_code=404, detail="Alert history record not found")

    es.update(
        index=ALERT_HISTORY_INDEX,
        id=alert_id,
        doc={
            "status": normalized_status,
            "status_updated_at": datetime.now(timezone.utc).isoformat(),
        },
        retry_on_conflict=3,
    )
    return {
        "message": "Alert status updated",
        "history_id": alert_id,
        "status": normalized_status,
    }


# --------------------------------------------------
# GET SECURITY ALERTS
# --------------------------------------------------

@app.get("/alerts")
def get_alerts():

    response = es.search(
        index="siem-events-*",
        query={
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-5m"
                            }
                        }
                    }
                ]
            }
        },
        size=1000,
        sort="@timestamp:desc"
    )


    # --------------------------------------------------
    # COUNT FAILED LOGINS BY IP OR LOCAL ENTITY
    # --------------------------------------------------

    failed_counts = Counter()
    failed_entity_by_doc = {}

    for hit in response["hits"]["hits"]:
        event = normalize_event(hit["_source"])
        event_details = event.get("event") or {}
        winlog_details = event.get("winlog") or {}
        event_code = str(event_details.get("code") or winlog_details.get("event_id") or event.get("event_id") or "")
        raw_type = event.get("event_type", [])
        event_types = ({str(x).strip().lower() for x in raw_type} if isinstance(raw_type, list)
                       else {str(raw_type).strip().lower()})
        if "login_failed" in event_types or event_code == "4625":
            entity_key = get_login_entity(event)
            failed_counts[entity_key] += 1
            failed_entity_by_doc[hit["_id"]] = entity_key

    # Five failures in the last five minutes from one IP/user/process/host.
    brute_force_entities = {key for key, count in failed_counts.items() if count >= 5}
    brute_force_ips = {key[1] for key in brute_force_entities if key and key[0] == "ip"}

    # --------------------------------------------------
    # FIND SUCCESSFUL LOGIN IPS
    # --------------------------------------------------

    successful_login_ips = set()

    for hit in response["hits"]["hits"]:

        event = normalize_event(hit["_source"])

        raw_event_type = event.get("event_type", [])
        event_types_for_success = (
            {str(item).lower() for item in raw_event_type}
            if isinstance(raw_event_type, list)
            else {str(raw_event_type).lower()}
        )
        event_details = event.get("event") or {}
        winlog_details = event.get("winlog") or {}
        event_code_for_success = str(
            event_details.get("code")
            or winlog_details.get("event_id")
            or event.get("event_id")
            or ""
        )
        source_ip_for_success = (
            event.get("source_ip")
            or (event.get("source") or {}).get("ip")
            or (winlog_details.get("event_data") or {}).get("IpAddress")
            or (winlog_details.get("event_data") or {}).get("IpAddressV6")
        )
        if isinstance(source_ip_for_success, list):
            source_ip_for_success = source_ip_for_success[0] if source_ip_for_success else None

        if "login_success" in event_types_for_success or event_code_for_success == "4624":
            if source_ip_for_success:
                successful_login_ips.add(str(source_ip_for_success))


    # --------------------------------------------------
    # FIND PORT SCAN IPS
    # --------------------------------------------------

    port_scan_ips = detect_port_scan(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )

    dns_activity_ips = detect_dns_activity(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )

    http_activity_ips = detect_http_activity(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )

    ssh_activity_ips = detect_ssh_activity(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )

    file_access_ips = detect_file_access(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )


    process_execution_ips = detect_process_execution(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )

    privilege_escalation_ips = detect_privilege_escalation(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )


    command_execution_ips = detect_command_execution(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )

    attack_chain_ips = detect_attack_chain(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )


    # --------------------------------------------------
    # MULTI-EVENT CORRELATION
    # --------------------------------------------------

    compromised_ips = (
        brute_force_ips
        & successful_login_ips
    )


    # --------------------------------------------------
    # USER & ENTITY BEHAVIOR ANALYSIS
    # --------------------------------------------------

    # UEBA anomaly detection uses the same recent event window as alert rules.
    # The behavior baseline uses a separate 24-hour window so it does not stay
    # empty whenever no events arrive during the last five minutes.
    recent_events = [
        normalize_event(hit["_source"])
        for hit in response["hits"]["hits"]
    ]

    baseline_response = es.search(
        index="siem-events-*",
        query={
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        },
        size=5000,
        sort="@timestamp:desc"
    )
    baseline_events = [
        normalize_event(hit["_source"])
        for hit in baseline_response["hits"]["hits"]
    ]

    # Load the previously saved baseline before comparing recent activity.
    historical_baseline = load_behavior_baseline()
    ueba_anomalies = detect_anomalous_behavior(
        recent_events,
        historical_baseline
    )

    # Learn normal behavior from the last 24 hours, independently of the
    # five-minute alert window.
    current_baseline = calculate_behavior_baseline(baseline_events)
    behavior_baseline = save_behavior_baseline(current_baseline)

    # --------------------------------------------------
    # CREATE ALERTS
    # --------------------------------------------------

    alerts = []

    # --------------------------------------------------
    # UEBA ANOMALY ALERTS
    # --------------------------------------------------

    for entity, anomaly in ueba_anomalies.items():

        entity_type = str(anomaly.get("entity_type") or "UNKNOWN").upper()
        anomaly_entity = anomaly.get("entity") or entity

        # A USER anomaly is keyed as "user:<name>"; that key is not an IP.
        # Keep source_ip empty unless the detector supplied a real IP.
        anomaly_username = anomaly.get("username")
        if not anomaly_username and entity_type in {"USER", "USER_IP_RELATIONSHIP"}:
            anomaly_username = anomaly_entity

        alert = {
            "alert": "UEBA Anomaly Detected",
            "source_ip": anomaly.get("source_ip") or None,
            "username": anomaly_username or None,
            "entity_type": entity_type,
            "entity_key": str(entity),
            "threat_type": anomaly["anomaly_type"],
            "risk_score": anomaly["risk_score"],
            "severity": anomaly["severity"],
            "activity_count": anomaly["activity_count"],
            "failed_login_count": anomaly["failed_login_count"],
            "baseline_activity": anomaly.get(
                "baseline_activity",
                0
            ),
            "relationship_activity_count": anomaly.get(
                "relationship_activity_count",
                0
            ),
            "known_source_ips": anomaly.get(
                "known_source_ips",
                []
            ),
            "detection_reason": anomaly.get(
                "detection_reason",
                "Unusual Behavior"
            ),
            "message": "Unusual user/entity behavior detected"
        }

        alerts.append(alert)

    for hit in response["hits"]["hits"]:

        event = normalize_event(hit["_source"])
        raw_event_type = event.get("event_type", [])
        if isinstance(raw_event_type, list):
            event_types = {str(item).lower() for item in raw_event_type}
        else:
            event_types = {str(raw_event_type).lower()} if raw_event_type else set()

        event_details = event.get("event") or {}
        winlog_details = event.get("winlog") or {}
        event_code = str(
            event_details.get("code")
            or winlog_details.get("event_id")
            or event.get("event_id")
            or ""
        )
        winlog_event_data = winlog_details.get("event_data") or {}
        source_ip = (
            event.get("source_ip")
            or (event.get("source") or {}).get("ip")
            or winlog_event_data.get("IpAddress")
            or winlog_event_data.get("IpAddressV6")
        )
        if isinstance(source_ip, list):
            source_ip = source_ip[0] if source_ip else None
        ip_reputation = check_ip_reputation(source_ip) if source_ip else None


        # --------------------------------------------------
        # MULTI-STAGE ATTACK CHAIN ALERT
        # --------------------------------------------------

        if source_ip in attack_chain_ips:
            alert = event.copy()

            if ip_reputation:
                alert["ip_reputation"] = ip_reputation["reputation"]
                alert["ip_threat_type"] = ip_reputation["threat_type"]
                alert["ip_reputation_risk"] = ip_reputation["risk_score"]
                alert["ip_reputation_confidence"] = ip_reputation["confidence"]

            alert["alert"] = "Multi-Stage Attack Chain Detected"
            alert["risk_score"] = 100
            alert["threat_type"] = (
                "Port Scan -> Brute Force -> Successful Login -> Privilege Escalation"
            )
            alert["severity"] = calculate_severity(100)
            alert["attack_chain"] = [
                "Port Scan",
                "Brute Force",
                "Successful Login",
                "Privilege Escalation"
            ]
            alert["attack_chain_source_ip"] = source_ip
            alerts.append(alert)

        # --------------------------------------------------
        # BRUTE FORCE ALERT
        # --------------------------------------------------

        elif (
            ("login_failed" in event_types or event_code == "4625")
            and (
                source_ip in brute_force_ips
                or get_login_entity(event) in brute_force_entities
            )
        ):

            alert = event.copy()

            alert["alert"] = (
                "Brute Force Attack Detected"
            )

            alert["risk_score"] = 80

            alert["severity"] = calculate_severity(80)

            alerts.append(alert)


        # --------------------------------------------------
        # PORT SCAN ALERT
        # --------------------------------------------------

        elif (
            source_ip in port_scan_ips
            and event.get("destination_port") is not None
        ):

            alert = event.copy()

            alert["alert"] = "Port Scan Detected"

            alert["risk_score"] = 70

            alert["threat_type"] = "Multiple Port Scan Activity"

            alert["severity"] = calculate_severity(70)

            alert["scanned_ports"] = sorted(
                list(port_scan_ips[source_ip]),
                key=lambda x: int(x) if x.isdigit() else x
            )

            alerts.append(alert)


        # --------------------------------------------------
        # SUSPICIOUS DNS ACTIVITY ALERT
        # --------------------------------------------------

        elif (
            event.get("event_type") == "dns_query"
            and source_ip in dns_activity_ips
        ):

            alert = event.copy()

            alert["alert"] = "Suspicious DNS Activity"

            alert["risk_score"] = 60

            alert["threat_type"] = "High Volume DNS Activity"

            alert["severity"] = calculate_severity(60)

            alert["dns_query_count"] = dns_activity_ips[source_ip]

            alerts.append(alert)


        # --------------------------------------------------
        # SUSPICIOUS HTTP ACTIVITY ALERT
        # --------------------------------------------------

        elif (
            event.get("event_type") == "http_request"
            and source_ip in http_activity_ips
        ):

            alert = event.copy()

            alert["alert"] = "Suspicious HTTP Activity"

            alert["risk_score"] = 50

            alert["threat_type"] = "High Volume HTTP Activity"

            alert["severity"] = calculate_severity(50)

            alert["http_request_count"] = http_activity_ips[source_ip]

            alerts.append(alert)


        # --------------------------------------------------
        # SUSPICIOUS SSH ACTIVITY ALERT
        # --------------------------------------------------

        elif (
            event.get("event_type") == "ssh_connection"
            and source_ip in ssh_activity_ips
        ):

            alert = event.copy()

            alert["alert"] = "Suspicious SSH Activity"

            alert["risk_score"] = 60

            alert["threat_type"] = "High Volume SSH Activity"

            alert["severity"] = calculate_severity(60)

            alert["ssh_connection_count"] = ssh_activity_ips[source_ip]

            alerts.append(alert)


        # --------------------------------------------------
        # SUSPICIOUS FILE ACCESS ALERT
        # --------------------------------------------------

        elif (
            event.get("event_type") == "file_access"
            and source_ip in file_access_ips
        ):

            alert = event.copy()

            alert["alert"] = "Suspicious File Access"

            alert["risk_score"] = 70

            alert["threat_type"] = "High Volume Sensitive File Access"

            alert["severity"] = calculate_severity(70)

            alert["file_access_count"] = file_access_ips[source_ip]

            alerts.append(alert)


        # --------------------------------------------------
        # SUSPICIOUS PROCESS EXECUTION ALERT
        # --------------------------------------------------

        elif (
            event.get("event_type") == "process_execution"
            and source_ip in process_execution_ips
        ):

            alert = event.copy()

            alert["alert"] = "Suspicious Process Execution"

            alert["risk_score"] = 65

            alert["threat_type"] = "High Volume Process Execution"

            alert["severity"] = calculate_severity(65)

            alert["process_execution_count"] = process_execution_ips[source_ip]

            alerts.append(alert)


        # --------------------------------------------------
        # SUSPICIOUS PRIVILEGE ESCALATION ALERT
        # --------------------------------------------------

        elif (
            event.get("event_type") == "privilege_escalation"
            and source_ip in privilege_escalation_ips
        ):

            alert = event.copy()
            alert["alert"] = "Suspicious Privilege Escalation"
            alert["risk_score"] = 75
            alert["threat_type"] = "Privilege Escalation Activity"
            alert["severity"] = calculate_severity(75)
            alert["privilege_escalation_count"] = privilege_escalation_ips[source_ip]
            alerts.append(alert)


        # --------------------------------------------------
        # SUSPICIOUS COMMAND EXECUTION ALERT
        # --------------------------------------------------

        elif (
            event.get("event_type") == "command_execution"
            and source_ip in command_execution_ips
        ):

            alert = event.copy()
            alert["alert"] = "Suspicious Command Execution"
            alert["risk_score"] = 70
            alert["threat_type"] = "High Volume Command Execution"
            alert["severity"] = calculate_severity(70)
            alert["command_execution_count"] = command_execution_ips[source_ip]
            alerts.append(alert)


        # --------------------------------------------------
        # ACCOUNT COMPROMISE ALERT
        # --------------------------------------------------

        elif (
            event.get("event_type") == "login_success"
            and source_ip in compromised_ips
        ):

            alert = event.copy()

            alert["alert"] = (
                "Possible Account Compromise"
            )

            alert["risk_score"] = 95

            alert["threat_type"] = (
                "Brute Force Followed by Successful Login"
            )

            alert["severity"] = calculate_severity(95)

            alerts.append(alert)


    # Save a durable copy so alert history survives the live five-minute window.
    try:
        save_alert_history(alerts)
    except Exception as exc:
        # Do not break live detection if history storage has a temporary issue.
        print("Alert history persistence error:", repr(exc))

    return {
        "total_alerts": len(alerts),
        "behavior_baseline": behavior_baseline,
        "alerts": alerts
    }


# --------------------------------------------------
# THREAT INVESTIGATION
# --------------------------------------------------

@app.get("/investigate/{source_ip}")
def investigate_ip(source_ip: str):

    response = es.search(
        index="siem-events-*",
        query={
            "term": {
                "source_ip.keyword": source_ip
            }
        },
        size=100,
        sort="@timestamp:desc"
    )

    events = []

    for hit in response["hits"]["hits"]:

        event = hit["_source"]

        event["id"] = hit["_id"]

        events.append(event)

    return {
        "source_ip": source_ip,
        "total_events": len(events),
        "events": events
    }


# --------------------------------------------------
# IP MONITORING
# --------------------------------------------------

@app.get("/ip-monitoring")
def ip_monitoring():

    response = es.search(
        index="siem-events-*",
        query={
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": "now-5m"
                            }
                        }
                    }
                ]
            }
        },
        size=500,
        sort="@timestamp:desc"
    )


    ip_data = {}


    for hit in response["hits"]["hits"]:

        event = hit["_source"]

        source_ip = event.get("source_ip")

        if not source_ip:
            continue


        if source_ip not in ip_data:

            ip_data[source_ip] = {
                "source_ip": source_ip,
                "failed_logins": 0,
                "successful_logins": 0,
                "total_events": 0
            }


        ip_data[source_ip]["total_events"] += 1


        if event.get("event_type") == "login_failed":

            ip_data[source_ip]["failed_logins"] += 1

        elif event.get("event_type") == "login_success":

            ip_data[source_ip]["successful_logins"] += 1


    # --------------------------------------------------
    # CALCULATE IP RISK
    # --------------------------------------------------

    monitored_ips = []


    for source_ip, data in ip_data.items():

        failed = data["failed_logins"]

        successful = data["successful_logins"]

        risk_score = 0


        if failed >= 5:

            risk_score = 80

        elif failed >= 3:

            risk_score = 50

        elif failed >= 1:

            risk_score = 20


        # --------------------------------------------------
        # BRUTE FORCE + SUCCESSFUL LOGIN
        # --------------------------------------------------

        if failed >= 5 and successful >= 1:

            risk_score = 95


        severity = calculate_severity(
            risk_score
        )


        # --------------------------------------------------
        # IP STATUS
        # --------------------------------------------------

        if failed >= 5:

            status = "Attack Detected"

        elif failed >= 3:

            status = "Suspicious"

        elif failed >= 1:

            status = "Monitoring"

        else:

            status = "Normal"


        monitored_ips.append({

            "source_ip": source_ip,

            "failed_logins": failed,

            "successful_logins": successful,

            "total_events": data["total_events"],

            "risk_score": risk_score,

            "severity": severity,

            "status": status

        })


    # --------------------------------------------------
    # SORT HIGHEST RISK FIRST
    # --------------------------------------------------

    monitored_ips.sort(
        key=lambda x: x["risk_score"],
        reverse=True
    )


    return {

        "total_ips": len(monitored_ips),

        "ips": monitored_ips

    }


# --------------------------------------------------
# SECURITY ANALYTICS
# --------------------------------------------------

@app.get("/analytics")
def security_analytics():

    response = es.search(
        index="siem-events-*",
        query={
            "range": {
                "@timestamp": {
                    "gte": "now-5m"
                }
            }
        },
        size=500
    )


    total_events = 0

    failed_logins = 0

    successful_logins = 0

    threat_events = 0


    severity_counts = Counter()

    ip_counts = Counter()

    failed_counts = Counter()

    successful_ips = set()
    port_data = {}
    dns_counts = Counter()
    ssh_counts = Counter()
    file_access_counts = Counter()
    process_execution_counts = Counter()
    privilege_escalation_counts = Counter()
    command_execution_counts = Counter()


    # --------------------------------------------------
    # FIRST PASS
    # COUNT EVENTS AND IPS
    # --------------------------------------------------

    for hit in response["hits"]["hits"]:

        event = normalize_event(hit["_source"])

        total_events += 1


        # ----------------------------------------------
        # LOGIN COUNTS
        # Support normalized events and raw Windows Security events.
        # Windows Event ID 4625 = failed logon; 4624 = successful logon.
        # ----------------------------------------------

        event_details = event.get("event") or {}
        winlog_details = event.get("winlog") or {}
        winlog_event_data = winlog_details.get("event_data") or {}
        event_code = str(
            event_details.get("code")
            or winlog_details.get("event_id")
            or event.get("event_id")
            or ""
        )
        raw_event_type = event.get("event_type") or []
        if isinstance(raw_event_type, list):
            event_types = {str(item).lower() for item in raw_event_type}
        else:
            event_types = {str(raw_event_type).lower()}

        source_ip = (
            event.get("source_ip")
            or (event.get("source") or {}).get("ip")
            or winlog_event_data.get("IpAddress")
            or winlog_event_data.get("IpAddressV6")
        )
        if isinstance(source_ip, list):
            source_ip = source_ip[0] if source_ip else None

        is_failed_login = "login_failed" in event_types or event_code == "4625"
        is_successful_login = "login_success" in event_types or event_code == "4624"

        if is_failed_login:
            failed_logins += 1
            if source_ip:
                failed_counts[str(source_ip)] += 1

        elif is_successful_login:
            successful_logins += 1
            if source_ip:
                successful_ips.add(str(source_ip))


        # ----------------------------------------------
        # SOURCE IP COUNTS
        # ----------------------------------------------

        # Use the normalized source IP from the login parsing above.
        if source_ip:

            ip_counts[str(source_ip)] += 1

            destination_port = event.get("destination_port")

            if destination_port is not None:

                if source_ip not in port_data:
                    port_data[source_ip] = set()

                port_data[source_ip].add(str(destination_port))

        if event.get("event_type") == "dns_query" and source_ip:
            dns_counts[source_ip] += 1

        if event.get("event_type") == "ssh_connection" and source_ip:
            ssh_counts[source_ip] += 1

        if event.get("event_type") == "file_access" and source_ip:
            file_access_counts[source_ip] += 1


        if event.get("event_type") == "process_execution" and source_ip:
            process_execution_counts[source_ip] += 1

        if event.get("event_type") == "privilege_escalation" and source_ip:
            privilege_escalation_counts[source_ip] += 1

        if event.get("event_type") == "command_execution" and source_ip:
            command_execution_counts[source_ip] += 1


    # --------------------------------------------------
    # FIND BRUTE FORCE IPS
    # --------------------------------------------------

    brute_force_ips = set()

    for source_ip, count in failed_counts.items():

        if count >= 5:

            brute_force_ips.add(source_ip)


    # --------------------------------------------------
    # FIND PORT SCAN IPS
    # --------------------------------------------------

    port_scan_ips = {
        source_ip
        for source_ip, ports in port_data.items()
        if len(ports) >= 5
    }

    dns_activity_ips = {
        source_ip
        for source_ip, count in dns_counts.items()
        if count >= 20
    }

    ssh_activity_ips = {
        source_ip
        for source_ip, count in ssh_counts.items()
        if count >= 20
    }

    file_access_ips = {
        source_ip
        for source_ip, count in file_access_counts.items()
        if count >= 20
    }


    process_execution_ips = {
        source_ip
        for source_ip, count in process_execution_counts.items()
        if count >= 20
    }

    privilege_escalation_ips = set(privilege_escalation_counts.keys())

    command_execution_ips = {
        source_ip
        for source_ip, count in command_execution_counts.items()
        if count >= 20
    }

    attack_chain_ips = detect_attack_chain(
        [hit["_source"] for hit in response["hits"]["hits"]]
    )


    # --------------------------------------------------
    # SECOND PASS
    # CALCULATE THREATS + SEVERITY
    # --------------------------------------------------

    for hit in response["hits"]["hits"]:

        event = normalize_event(hit["_source"])

        event_details = event.get("event") or {}
        winlog_details = event.get("winlog") or {}
        winlog_event_data = winlog_details.get("event_data") or {}
        event_code = str(
            event_details.get("code")
            or winlog_details.get("event_id")
            or event.get("event_id")
            or ""
        )
        raw_event_type = event.get("event_type") or []
        if isinstance(raw_event_type, list):
            event_types = {str(item).lower() for item in raw_event_type}
        else:
            event_types = {str(raw_event_type).lower()}
        source_ip = (
            event.get("source_ip")
            or (event.get("source") or {}).get("ip")
            or winlog_event_data.get("IpAddress")
            or winlog_event_data.get("IpAddressV6")
        )
        if isinstance(source_ip, list):
            source_ip = source_ip[0] if source_ip else None

        risk_score = 0

        is_threat = False


        # ----------------------------------------------
        # MULTI-STAGE ATTACK CHAIN
        # ----------------------------------------------

        if source_ip in attack_chain_ips:

            risk_score = 100
            is_threat = True


        # ----------------------------------------------
        # BRUTE FORCE
        # ----------------------------------------------

        elif (
            event.get("event_type") == "login_failed"
            and source_ip in brute_force_ips
        ):

            risk_score = 80

            is_threat = True


        # ----------------------------------------------
        # ACCOUNT COMPROMISE
        # ----------------------------------------------

        elif (
            ("login_success" in event_types or event_code == "4624")
            and source_ip in brute_force_ips
            and source_ip in successful_ips
        ):

            risk_score = 95

            is_threat = True


        # ----------------------------------------------
        # PORT SCAN
        # ----------------------------------------------

        elif (
            event.get("destination_port") is not None
            and source_ip in port_scan_ips
        ):

            risk_score = 70

            is_threat = True


        # ----------------------------------------------
        # SUSPICIOUS DNS ACTIVITY
        # ----------------------------------------------

        elif (
            event.get("event_type") == "dns_query"
            and source_ip in dns_activity_ips
        ):

            risk_score = 60

            is_threat = True


        # ----------------------------------------------
        # SUSPICIOUS SSH ACTIVITY
        # ----------------------------------------------

        elif (
            event.get("event_type") == "ssh_connection"
            and source_ip in ssh_activity_ips
        ):

            risk_score = 60

            is_threat = True


        # ----------------------------------------------
        # SUSPICIOUS FILE ACCESS
        # ----------------------------------------------

        elif (
            event.get("event_type") == "file_access"
            and source_ip in file_access_ips
        ):

            risk_score = 70

            is_threat = True


        # ----------------------------------------------
        # SUSPICIOUS PROCESS EXECUTION
        # ----------------------------------------------

        elif (
            event.get("event_type") == "process_execution"
            and source_ip in process_execution_ips
        ):

            risk_score = 65

            is_threat = True


        # ----------------------------------------------
        # SUSPICIOUS PRIVILEGE ESCALATION
        # ----------------------------------------------

        elif (
            event.get("event_type") == "privilege_escalation"
            and source_ip in privilege_escalation_ips
        ):

            risk_score = 75
            is_threat = True


        # ----------------------------------------------
        # SUSPICIOUS COMMAND EXECUTION
        # ----------------------------------------------

        elif (
            event.get("event_type") == "command_execution"
            and source_ip in command_execution_ips
        ):

            risk_score = 70
            is_threat = True


        # ----------------------------------------------
        # SEVERITY
        # ----------------------------------------------

        if is_threat:

            severity = calculate_severity(
                risk_score
            )

            severity_counts[severity] += 1


            threat_events += 1


    # --------------------------------------------------
    # TOP SOURCE IPS
    # --------------------------------------------------

    top_ips = []


    for ip, count in ip_counts.most_common(10):

        top_ips.append({

            "source_ip": ip,

            "event_count": count

        })


    # --------------------------------------------------
    # RETURN SECURITY ANALYTICS
    # --------------------------------------------------

    return {

        "time_window": "Last 5 minutes",

        "total_events": total_events,

        "failed_logins": failed_logins,

        "successful_logins": successful_logins,

        "threat_events": threat_events,

        "severity_distribution": {

            "CRITICAL": severity_counts.get(
                "CRITICAL",
                0
            ),

            "HIGH": severity_counts.get(
                "HIGH",
                0
            ),

            "MEDIUM": severity_counts.get(
                "MEDIUM",
                0
            ),

            "LOW": severity_counts.get(
                "LOW",
                0
            )

        },

        "top_source_ips": top_ips

    }


# --------------------------------------------------
# REAL-TIME WEBSOCKET
# --------------------------------------------------

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    Stream the latest SIEM events to the React frontend.

    The route accepts the connection before querying Elasticsearch so the
    browser does not receive a 404/handshake failure for this endpoint.
    """
    await websocket.accept()
    print("WebSocket client connected: /ws/events")

    try:
        while True:
            try:
                response = es.search(
                    index="siem-events-*",
                    query={"match_all": {}},
                    size=100,
                    sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                )

                events = []
                for hit in response["hits"]["hits"]:
                    event = normalize_event(hit["_source"])
                    event["id"] = hit["_id"]
                    events.append(event)

                await websocket.send_json({"events": events})
                await asyncio.sleep(2)

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                print("WebSocket event-stream error:", repr(exc))
                # Keep the socket alive briefly so a temporary ES issue
                # does not immediately terminate the frontend connection.
                await websocket.send_json({
                    "events": [],
                    "error": "Unable to retrieve events from Elasticsearch"
                })
                await asyncio.sleep(3)

    except Exception as exc:
        print("WebSocket disconnected:", repr(exc))
