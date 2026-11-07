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
import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv
import jwt
from pwdlib import PasswordHash
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional


# --------------------------------------------------
# AUTHENTICATION CONFIGURATION
# --------------------------------------------------

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=True)

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if not SECRET_KEY or not ADMIN_USERNAME or not ADMIN_PASSWORD_HASH:
    raise RuntimeError(
        "Missing SECRET_KEY, ADMIN_USERNAME, or ADMIN_PASSWORD_HASH in backend .env"
    )

password_hasher = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def create_access_token(subject: str):
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {"sub": subject, "exp": expires_at}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_error = HTTPException(
        status_code=401,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
        username = payload.get("sub")
        if not username or username != ADMIN_USERNAME:
            raise credentials_error
        return {"username": username, "role": "admin"}
    except jwt.InvalidTokenError:
        raise credentials_error


app = FastAPI(title="SIEM Backend")
SIEM_IP_REPUTATION_ENRICHMENT_VERSION = "2.0"


# --------------------------------------------------
# AUTHENTICATION ENDPOINTS
# --------------------------------------------------

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate the configured administrator and issue a JWT access token."""
    username_ok = form_data.username == ADMIN_USERNAME
    password_ok = password_hasher.verify(
        form_data.password,
        ADMIN_PASSWORD_HASH,
    )
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(form_data.username)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "username": form_data.username,
        "role": "admin",
    }


@app.get("/auth/me")
def read_current_user(current_user: dict = Depends(get_current_user)):
    """Return the identity associated with a valid access token."""
    return current_user


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


def enrich_alert_with_ip_reputation(alert):
    """Attach local threat-intelligence metadata to any alert with a source IP."""
    source_ip = (
        alert.get("source_ip")
        or alert.get("attack_chain_source_ip")
        or (alert.get("source") or {}).get("ip")
    )
    if isinstance(source_ip, list):
        source_ip = next((str(value).strip() for value in source_ip if value), None)
    if not source_ip:
        return alert

    source_ip = str(source_ip).strip()
    if not source_ip:
        return alert

    try:
        reputation = check_ip_reputation(source_ip)
    except Exception as exc:
        print("IP reputation lookup error:", repr(exc))
        reputation = None

    if not isinstance(reputation, dict):
        return alert

    alert["ip_reputation"] = reputation.get("reputation", "UNKNOWN")
    alert["ip_threat_type"] = reputation.get("threat_type", "No local match")
    alert["ip_reputation_risk"] = reputation.get("risk_score", 0)
    alert["ip_reputation_confidence"] = reputation.get("confidence", 0)
    alert["ip_reputation_source"] = reputation.get("source", "Local threat intelligence")
    alert["ip_reputation_description"] = reputation.get("description", "")
    alert["ip_reputation_details"] = reputation
    return alert


# --------------------------------------------------
# EVENT NORMALIZATION
# --------------------------------------------------

def normalize_event(event):
    """Return a copy with common Windows and nested fields normalized."""
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
    username = str(data.get("TargetUserName") or data.get("SubjectUserName") or "").strip()
    process = str(data.get("ProcessName") or "").strip().lower()
    host = str((event.get("host") or {}).get("name") or winlog.get("computer_name") or "unknown-host").strip().lower()
    if username and username != "-":
        return ("user", host, username.lower())
    if process:
        return ("process", host, process)
    return ("host", host)


# --------------------------------------------------
# DETECTION HELPERS
# --------------------------------------------------

def detect_port_scan(events, threshold=5):
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


def detect_dns_activity(events, threshold=20):
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


def detect_http_activity(events, threshold=20):
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


def detect_ssh_activity(events, threshold=20):
    ssh_counts = Counter()
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


def detect_file_access(events, threshold=20):
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


def detect_process_execution(events, threshold=20):
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


def detect_privilege_escalation(events):
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


def detect_command_execution(events, threshold=20):
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


def detect_attack_chain(events):
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
        if has_port_scan and has_brute_force and has_success and has_privilege_escalation:
            attack_chain_ips.add(source_ip)

    return attack_chain_ips


# --------------------------------------------------
# ROOT & HEALTH
# --------------------------------------------------

@app.get("/")
def root():
    return {"message": "SIEM Backend is running"}


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

@app.get("/events", dependencies=[Depends(get_current_user)])
def get_events(limit: int = 100, event_id: int = None):
    limit = max(1, min(limit, 500))
    if event_id is not None:
        query = {"term": {"winlog.event_id": event_id}}
    else:
        query = {"match_all": {}}

    response = es.search(
        index="siem-events-*",
        query=query,
        size=limit,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
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

@app.get("/hosts", dependencies=[Depends(get_current_user)])
def get_hosts():
    inventory_response = es.search(
        index="siem-events-*",
        query={"match_all": {}},
        size=0,
        aggs={
            "hosts": {
                "terms": {
                    "field": "host.hostname.keyword",
                    "size": 100
                }
            }
        }
    )

    hosts_by_name = {}
    for bucket in inventory_response.get("aggregations", {}).get("hosts", {}).get("buckets", []):
        hostname = str(bucket.get("key", "")).strip()
        if not hostname:
            continue
        hosts_by_name[hostname.lower()] = {
            "hostname": hostname,
            "event_count": 0,
            "threat_count": 0,
            "failed_login_count": 0,
            "real_failed_login_count": 0,
            "simulation_failed_login_count": 0,
            "risk_score": 0,
            "severity": "LOW",
            "status": "NORMAL",
            "simulation_only": False
        }

    recent_response = es.search(
        index="siem-events-*",
        query={"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-24h"}}}
        ]}},
        size=10000,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    )

    for hit in recent_response.get("hits", {}).get("hits", []):
        event = normalize_event(hit.get("_source", {}))
        host_info = event.get("host") or {}
        winlog_info = event.get("winlog") or {}
        hostname = (
            host_info.get("hostname")
            or host_info.get("name")
            or winlog_info.get("computer_name")
        )
        if not hostname:
            continue

        hostname = str(hostname).strip()
        key = hostname.lower()

        tags = event.get("tags") or []
        threat_type = str(event.get("threat_type") or "")
        message = str(event.get("message") or "")
        simulation_only = (
            "siem_simulation" in tags
            or "test_event" in tags
            or "SIMULATION" in threat_type.upper()
            or "SIMULATED" in message.upper()
        )
        if key not in hosts_by_name:
            if simulation_only:
                continue
            hosts_by_name[key] = {
                "hostname": hostname,
                "event_count": 0,
                "threat_count": 0,
                "failed_login_count": 0,
                "real_failed_login_count": 0,
                "simulation_failed_login_count": 0,
                "risk_score": 0,
                "severity": "LOW",
                "status": "NORMAL",
                "simulation_only": False
            }

        host = hosts_by_name[key]
        host["event_count"] += 1

        event_type = event.get("event_type", [])
        event_types = (
            {str(value).strip().lower() for value in event_type}
            if isinstance(event_type, list)
            else {str(event_type).strip().lower()}
        )
        event_details = event.get("event") or {}
        event_code = str(
            event_details.get("code")
            or winlog_info.get("event_id")
            or event.get("event_id")
            or ""
        )

        if "login_failed" in event_types or event_code == "4625":
            host["failed_login_count"] += 1
            if simulation_only:
                host["simulation_failed_login_count"] += 1
                host["simulation_only"] = True
            else:
                host["real_failed_login_count"] += 1

    for host in hosts_by_name.values():
        failed = host["real_failed_login_count"]
        if failed >= 10:
            risk_score = 95
        elif failed >= 5:
            risk_score = 80
        elif failed >= 3:
            risk_score = 50
        elif failed >= 1:
            risk_score = 20
        else:
            risk_score = 0

        host["risk_score"] = risk_score
        host["severity"] = calculate_severity(risk_score)

        if risk_score >= 80:
            host["status"] = "CRITICAL"
        elif risk_score >= 30:
            host["status"] = "WARNING"
        else:
            host["status"] = "NORMAL"

        host["threat_count"] = host["real_failed_login_count"]

    hosts = sorted(
        hosts_by_name.values(),
        key=lambda item: (item["risk_score"], item["event_count"]),
        reverse=True
    )

    return {
        "total_hosts": len(hosts),
        "time_window": "Last 24 hours",
        "hosts": hosts
    }


# --------------------------------------------------
# SAFE SIMULATED EVENT GENERATORS
# --------------------------------------------------

@app.post("/test/brute-force", dependencies=[Depends(get_current_user)])
def create_brute_force_test_events():
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


@app.post("/test/port-scan", dependencies=[Depends(get_current_user)])
def create_port_scan_test_events():
    """Insert synthetic port-scan events across 6 distinct ports."""
    now = datetime.now(timezone.utc)
    index_name = f"siem-events-{now.strftime('%Y.%m.%d')}"
    test_ip = "198.51.100.50"
    ports = [21, 22, 80, 443, 3389, 8080]
    inserted_ids = []

    for port in ports:
        document = {
            "@timestamp": now.isoformat(),
            "event_type": "network_connection",
            "source_ip": test_ip,
            "destination_port": port,
            "message": f"SIMULATED port probe on port {port}",
            "threat_type": "SIMULATION ONLY - Port Scan Test",
            "host": {
                "name": "siem-test-host",
                "hostname": "SIEM-TEST-HOST"
            },
            "tags": ["siem_simulation", "test_event"]
        }
        result = es.index(index=index_name, document=document, refresh=True)
        inserted_ids.append(result.get("_id"))

    return {
        "message": f"Inserted {len(inserted_ids)} synthetic port-scan probes.",
        "simulation_only": True,
        "source_ip": test_ip,
        "scanned_ports": ports
    }


@app.post("/test/attack-chain", dependencies=[Depends(get_current_user)])
def create_attack_chain_test_events():
    """Insert synthetic events representing a 4-stage intrusion chain."""
    now = datetime.now(timezone.utc)
    index_name = f"siem-events-{now.strftime('%Y.%m.%d')}"
    test_ip = "198.51.100.99"
    test_user = "compromised_admin"
    inserted_ids = []

    # 1. Port scan stage: probe 5 unique ports
    for port in [21, 22, 80, 443, 3389]:
        doc = {
            "@timestamp": now.isoformat(),
            "event_type": "network_connection",
            "source_ip": test_ip,
            "destination_port": port,
            "message": f"SIMULATED port probe on port {port}",
            "threat_type": "SIMULATION ONLY - Attack Chain Test",
            "host": {"name": "siem-test-host", "hostname": "SIEM-TEST-HOST"},
            "tags": ["siem_simulation", "test_event"]
        }
        res = es.index(index=index_name, document=doc, refresh=True)
        inserted_ids.append(res.get("_id"))

    # 2. Brute-force stage: 5 failed logins (Windows Event ID 4625)
    for _ in range(5):
        doc = {
            "@timestamp": now.isoformat(),
            "event_type": ["windows_security_event", "login_failed"],
            "event": {"code": "4625", "action": "Logon", "outcome": "failure"},
            "winlog": {
                "event_id": "4625",
                "computer_name": "SIEM-TEST-HOST",
                "event_data": {"TargetUserName": test_user, "IpAddress": test_ip}
            },
            "username": test_user,
            "source_ip": test_ip,
            "message": "SIMULATED logon failure during brute-force phase",
            "threat_type": "SIMULATION ONLY - Attack Chain Test",
            "host": {"name": "siem-test-host", "hostname": "SIEM-TEST-HOST"},
            "tags": ["siem_simulation", "test_event"]
        }
        res = es.index(index=index_name, document=doc, refresh=True)
        inserted_ids.append(res.get("_id"))

    # 3. Successful login stage: Windows Event ID 4624
    doc_success = {
        "@timestamp": now.isoformat(),
        "event_type": ["windows_security_event", "login_success"],
        "event": {"code": "4624", "action": "Logon", "outcome": "success"},
        "winlog": {
            "event_id": "4624",
            "computer_name": "SIEM-TEST-HOST",
            "event_data": {"TargetUserName": test_user, "IpAddress": test_ip}
        },
        "username": test_user,
        "source_ip": test_ip,
        "message": "SIMULATED successful logon after brute-force",
        "threat_type": "SIMULATION ONLY - Attack Chain Test",
        "host": {"name": "siem-test-host", "hostname": "SIEM-TEST-HOST"},
        "tags": ["siem_simulation", "test_event"]
    }
    res_success = es.index(index=index_name, document=doc_success, refresh=True)
    inserted_ids.append(res_success.get("_id"))

    # 4. Privilege escalation stage: Windows Event ID 4672
    doc_priv = {
        "@timestamp": now.isoformat(),
        "event_type": ["windows_security_event", "privilege_escalation"],
        "event": {"code": "4672", "action": "Special Privileges Assigned"},
        "winlog": {
            "event_id": "4672",
            "computer_name": "SIEM-TEST-HOST",
            "event_data": {"SubjectUserName": test_user, "IpAddress": test_ip}
        },
        "username": test_user,
        "source_ip": test_ip,
        "message": "SIMULATED privilege escalation to administrator",
        "threat_type": "SIMULATION ONLY - Attack Chain Test",
        "host": {"name": "siem-test-host", "hostname": "SIEM-TEST-HOST"},
        "tags": ["siem_simulation", "test_event"]
    }
    res_priv = es.index(index=index_name, document=doc_priv, refresh=True)
    inserted_ids.append(res_priv.get("_id"))

    return {
        "message": "Inserted multi-stage attack chain simulation events.",
        "simulation_only": True,
        "source_ip": test_ip,
        "username": test_user,
        "stages": ["Port Scan", "Brute Force", "Successful Login", "Privilege Escalation"],
        "events_inserted": len(inserted_ids)
    }


# --------------------------------------------------
# PERSISTENT ALERT HISTORY
# --------------------------------------------------

ALERT_HISTORY_INDEX = "siem-alert-history"


def save_alert_history(alerts):
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

        if is_ueba:
            entity_type = str(alert.get("entity_type") or "UNKNOWN").upper()
            entity_key = str(alert.get("entity_key") or "")
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
            "ip_reputation": alert.get("ip_reputation"),
            "ip_threat_type": alert.get("ip_threat_type"),
            "ip_reputation_risk": alert.get("ip_reputation_risk"),
            "ip_reputation_confidence": alert.get("ip_reputation_confidence"),
            "ip_reputation_source": alert.get("ip_reputation_source"),
            "ip_reputation_description": alert.get("ip_reputation_description"),
            "ip_reputation_details": alert.get("ip_reputation_details"),
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


@app.get("/alert-history", dependencies=[Depends(get_current_user)])
def get_alert_history(limit: int = 100, offset: int = 0, status: str = None, severity: str = None, q: str = None):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    filters = []
    if status:
        normalized_status = status.strip().upper()
        if normalized_status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
            raise HTTPException(
                status_code=400,
                detail="status must be OPEN, ACKNOWLEDGED, or RESOLVED"
            )
        filters.append({"term": {"status.keyword": normalized_status}})

    if severity:
        normalized_severity = severity.strip().upper()
        if normalized_severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise HTTPException(
                status_code=400,
                detail="severity must be CRITICAL, HIGH, MEDIUM, or LOW"
            )
        filters.append({"term": {"severity.keyword": normalized_severity}})

    search_text = (q or "").strip()
    must = []
    if search_text:
        must.append({
            "multi_match": {
                "query": search_text,
                "type": "best_fields",
                "operator": "and",
                "fields": [
                    "alert", "threat_type", "username", "source_ip", "host",
                    "message", "description", "event_type", "rule_name",
                    "user", "destination_ip", "status", "severity"
                ]
            }
        })

    query = {"bool": {"filter": filters, "must": must}} if (filters or must) else {"match_all": {}}

    try:
        response = es.search(
            index=ALERT_HISTORY_INDEX,
            query=query,
            from_=offset,
            size=limit,
            sort=[{"last_seen": {"order": "desc", "unmapped_type": "date"}}],
        )
    except Exception as exc:
        if "index_not_found_exception" in str(exc):
            return {
                "total": 0,
                "limit": limit,
                "offset": offset,
                "alerts": []
            }
        raise

    records = []
    for hit in response["hits"]["hits"]:
        record = hit["_source"].copy()
        record["history_id"] = hit["_id"]
        records.append(record)

    total = response["hits"]["total"]
    total_value = total["value"] if isinstance(total, dict) else total

    return {
        "total": total_value,
        "limit": limit,
        "offset": offset,
        "alerts": records
    }


@app.patch("/alert-history/{alert_id}/status", dependencies=[Depends(get_current_user)])
def update_alert_history_status(alert_id: str, status: str):
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

@app.get("/alerts", dependencies=[Depends(get_current_user)])
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

    brute_force_entities = {key for key, count in failed_counts.items() if count >= 5}
    brute_force_ips = {key[1] for key in brute_force_entities if key and key[0] == "ip"}

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

    port_scan_ips = detect_port_scan([hit["_source"] for hit in response["hits"]["hits"]])
    dns_activity_ips = detect_dns_activity([hit["_source"] for hit in response["hits"]["hits"]])
    http_activity_ips = detect_http_activity([hit["_source"] for hit in response["hits"]["hits"]])
    ssh_activity_ips = detect_ssh_activity([hit["_source"] for hit in response["hits"]["hits"]])
    file_access_ips = detect_file_access([hit["_source"] for hit in response["hits"]["hits"]])
    process_execution_ips = detect_process_execution([hit["_source"] for hit in response["hits"]["hits"]])
    privilege_escalation_ips = detect_privilege_escalation([hit["_source"] for hit in response["hits"]["hits"]])
    command_execution_ips = detect_command_execution([hit["_source"] for hit in response["hits"]["hits"]])
    attack_chain_ips = detect_attack_chain([hit["_source"] for hit in response["hits"]["hits"]])

    compromised_ips = brute_force_ips & successful_login_ips

    # UEBA detection with 24-hour analysis window
    ueba_response = es.search(
        index="siem-events-*",
        query={"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-24h"}}}
        ]}},
        size=5000,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    )
    recent_events = [
        normalize_event(hit["_source"])
        for hit in ueba_response["hits"]["hits"]
    ]

    historical_baseline = load_behavior_baseline()
    ueba_anomalies = detect_anomalous_behavior(
        recent_events,
        historical_baseline
    )

    baseline_response = es.search(
        index="siem-events-*",
        query={"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-7d"}}}
        ]}},
        size=10000,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    )
    baseline_events = [
        normalize_event(hit["_source"])
        for hit in baseline_response["hits"]["hits"]
    ]
    current_baseline = calculate_behavior_baseline(baseline_events)
    behavior_baseline = save_behavior_baseline(current_baseline)

    alerts = []

    for entity, anomaly in ueba_anomalies.items():
        entity_type = str(anomaly.get("entity_type") or "UNKNOWN").upper()
        anomaly_entity = anomaly.get("entity") or entity
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
            "baseline_activity": anomaly.get("baseline_activity", 0),
            "relationship_activity_count": anomaly.get("relationship_activity_count", 0),
            "known_source_ips": anomaly.get("known_source_ips", []),
            "detection_reason": anomaly.get("detection_reason", "Unusual Behavior"),
            "message": "Unusual user/entity behavior detected"
        }
        alert = enrich_alert_with_ip_reputation(alert)
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

        if source_ip in attack_chain_ips:
            alert = event.copy()
            if ip_reputation:
                alert["ip_reputation"] = ip_reputation["reputation"]
                alert["ip_threat_type"] = ip_reputation["threat_type"]
                alert["ip_reputation_risk"] = ip_reputation["risk_score"]
                alert["ip_reputation_confidence"] = ip_reputation["confidence"]

            alert["alert"] = "Multi-Stage Attack Chain Detected"
            alert["risk_score"] = 100
            alert["threat_type"] = "Port Scan -> Brute Force -> Successful Login -> Privilege Escalation"
            alert["severity"] = calculate_severity(100)
            alert["attack_chain"] = [
                "Port Scan", "Brute Force", "Successful Login", "Privilege Escalation"
            ]
            alert["attack_chain_source_ip"] = source_ip
            alerts.append(alert)

        elif (
            ("login_failed" in event_types or event_code == "4625")
            and (
                source_ip in brute_force_ips
                or get_login_entity(event) in brute_force_entities
            )
        ):
            alert = event.copy()
            alert["alert"] = "Brute Force Attack Detected"
            alert["risk_score"] = 80
            alert["severity"] = calculate_severity(80)
            alerts.append(alert)

        elif (
            event.get("destination_port") is not None
            and source_ip in port_scan_ips
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

        elif (
            event.get("event_type") == "login_success"
            and source_ip in compromised_ips
        ):
            alert = event.copy()
            alert["alert"] = "Possible Account Compromise"
            alert["risk_score"] = 95
            alert["threat_type"] = "Brute Force Followed by Successful Login"
            alert["severity"] = calculate_severity(95)
            alerts.append(alert)

    alerts = [enrich_alert_with_ip_reputation(alert) for alert in alerts]

    try:
        save_alert_history(alerts)
    except Exception as exc:
        print("Alert history persistence error:", repr(exc))

    return {
        "total_alerts": len(alerts),
        "behavior_baseline": behavior_baseline,
        "alerts": alerts
    }


# --------------------------------------------------
# THREAT INVESTIGATION
# --------------------------------------------------

@app.get("/investigate/{source_ip}", dependencies=[Depends(get_current_user)])
def investigate_ip(source_ip: str):
    source_ip = source_ip.strip()
    if not source_ip:
        raise HTTPException(status_code=400, detail="source_ip is required")

    ip_fields = [
        "source_ip",
        "source_ip.keyword",
        "source.ip",
        "source.ip.keyword",
        "winlog.event_data.IpAddress",
        "winlog.event_data.IpAddressV6",
    ]

    should_queries = []
    for field in ip_fields:
        should_queries.append({"term": {field: source_ip}})
        should_queries.append({"match_phrase": {field: source_ip}})

    response = es.search(
        index="siem-events-*",
        query={
            "bool": {
                "should": should_queries,
                "minimum_should_match": 1,
            }
        },
        size=500,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    )

    events = []
    seen_ids = set()

    for hit in response["hits"]["hits"]:
        event = normalize_event(hit.get("_source", {}))
        event_ip = event.get("source_ip")

        if isinstance(event_ip, list):
            matches = source_ip in [str(value).strip() for value in event_ip]
        else:
            matches = str(event_ip or "").strip() == source_ip

        if not matches:
            continue

        document_id = hit.get("_id")
        if document_id in seen_ids:
            continue
        seen_ids.add(document_id)

        event["id"] = document_id
        events.append(event)

    return {
        "source_ip": source_ip,
        "total_events": len(events),
        "events": events,
    }


# --------------------------------------------------
# IP MONITORING
# --------------------------------------------------

@app.get("/ip-monitoring", dependencies=[Depends(get_current_user)])
def ip_monitoring():
    response = es.search(
        index="siem-events-*",
        query={
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        },
        size=10000,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    )

    ip_data = {}

    for hit in response["hits"]["hits"]:
        event = normalize_event(hit.get("_source", {}))
        source_ip = event.get("source_ip")

        if isinstance(source_ip, list):
            source_ip = next((str(value).strip() for value in source_ip if value), None)
        if not source_ip:
            continue
        source_ip = str(source_ip).strip()
        if source_ip in {"", "-", "::", "::1", "0.0.0.0", "127.0.0.1"}:
            continue

        if source_ip not in ip_data:
            ip_data[source_ip] = {
                "source_ip": source_ip,
                "failed_logins": 0,
                "successful_logins": 0,
                "total_events": 0,
            }

        data = ip_data[source_ip]
        data["total_events"] += 1

        event_type = event.get("event_type", [])
        if isinstance(event_type, list):
            event_types = {str(value).strip().lower() for value in event_type}
        else:
            event_types = {str(event_type).strip().lower()}

        event_details = event.get("event") or {}
        winlog_details = event.get("winlog") or {}
        event_code = str(
            event_details.get("code")
            or winlog_details.get("event_id")
            or event.get("event_id")
            or ""
        )

        if "login_failed" in event_types or event_code == "4625":
            data["failed_logins"] += 1
        elif "login_success" in event_types or event_code == "4624":
            data["successful_logins"] += 1

    monitored_ips = []
    for source_ip, data in ip_data.items():
        failed = data["failed_logins"]
        successful = data["successful_logins"]

        if failed >= 5 and successful >= 1:
            risk_score = 95
        elif failed >= 5:
            risk_score = 80
        elif failed >= 3:
            risk_score = 50
        elif failed >= 1:
            risk_score = 20
        else:
            risk_score = 0

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
            "severity": calculate_severity(risk_score),
            "status": status,
        })

    monitored_ips.sort(
        key=lambda item: (item["risk_score"], item["total_events"]),
        reverse=True,
    )

    return {
        "time_window": "Last 24 hours",
        "total_ips": len(monitored_ips),
        "ips": monitored_ips,
    }


# --------------------------------------------------
# SECURITY ANALYTICS (24-HOUR & UNIFIED SEVERITY)
# --------------------------------------------------

@app.get("/analytics", dependencies=[Depends(get_current_user)])
def security_analytics():
    response = es.search(
        index="siem-events-*",
        query={
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        },
        size=10000,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    )

    total_events = 0
    failed_logins = 0
    successful_logins = 0
    threat_events = 0

    severity_counts = Counter()
    ip_counts = Counter()
    failed_counts = Counter()

    for hit in response["hits"]["hits"]:
        event = normalize_event(hit["_source"])
        total_events += 1

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

        is_failed = "login_failed" in event_types or event_code == "4625"
        is_success = "login_success" in event_types or event_code == "4624"

        if is_failed:
            failed_logins += 1
            if source_ip:
                failed_counts[str(source_ip)] += 1
        elif is_success:
            successful_logins += 1

        if source_ip and str(source_ip) not in {"", "-", "::", "::1", "0.0.0.0", "127.0.0.1"}:
            ip_counts[str(source_ip)] += 1

        threat_type = str(event.get("threat_type") or "")
        tags = event.get("tags") or []
        if threat_type or "threat" in tags or "attack" in threat_type.lower():
            threat_events += 1
            sev = str(event.get("severity") or "").upper()
            if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity_counts[sev] += 1

    try:
        history_response = es.search(
            index=ALERT_HISTORY_INDEX,
            query={"match_all": {}},
            size=1000,
        )
        for hit in history_response.get("hits", {}).get("hits", []):
            rec = hit.get("_source", {})
            sev = str(rec.get("severity") or "").upper()
            if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity_counts[sev] += 1
    except Exception as exc:
        print("Note: alert history check during analytics skipped:", repr(exc))

    top_ips = []
    for ip, count in ip_counts.most_common(10):
        top_ips.append({
            "source_ip": ip,
            "event_count": count
        })

    return {
        "time_window": "Last 24 hours",
        "total_events": total_events,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "threat_events": threat_events + sum(severity_counts.values()),
        "severity_distribution": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
        },
        "top_source_ips": top_ips
    }


# --------------------------------------------------
# SECURITY INCIDENT MANAGEMENT
# --------------------------------------------------

INCIDENTS_INDEX = "siem-incidents"


class CreateIncidentRequest(BaseModel):
    alert_history_id: str
    assigned_to: Optional[str] = None
    priority: Optional[str] = None


class UpdateIncidentRequest(BaseModel):
    assigned_to: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None


class IncidentNoteRequest(BaseModel):
    note: str
    author: Optional[str] = None


@app.get("/incidents", dependencies=[Depends(get_current_user)])
def get_incidents(limit: int = 100, status: Optional[str] = None):
    limit = max(1, min(limit, 500))
    normalized_status = status.strip().upper() if status else None

    allowed_statuses = {"OPEN", "INVESTIGATING", "RESOLVED"}
    if normalized_status and normalized_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="status must be OPEN, INVESTIGATING, or RESOLVED"
        )

    query = (
        {"match": {"status": normalized_status}}
        if normalized_status else {"match_all": {}}
    )

    try:
        response = es.search(
            index=INCIDENTS_INDEX,
            query=query,
            size=limit,
            sort=[{"updated_at": {"order": "desc", "unmapped_type": "date"}}]
        )
    except Exception as exc:
        if "index_not_found_exception" in str(exc):
            return {"total": 0, "incidents": []}
        raise

    incidents = []
    for hit in response["hits"]["hits"]:
        incident = hit["_source"].copy()
        incident["incident_id"] = hit["_id"]
        incidents.append(incident)

    total = response["hits"]["total"]
    total_value = total["value"] if isinstance(total, dict) else total
    return {"total": total_value, "incidents": incidents}


@app.post("/incidents", dependencies=[Depends(get_current_user)])
def create_incident(request: CreateIncidentRequest):
    alert_id = request.alert_history_id.strip()
    if not alert_id:
        raise HTTPException(status_code=400, detail="alert_history_id is required")

    try:
        alert_result = es.get(index=ALERT_HISTORY_INDEX, id=alert_id)
    except Exception as exc:
        if "not_found" in str(exc).lower() or "404" in str(exc):
            raise HTTPException(
                status_code=404,
                detail="Alert history record not found"
            )
        if "index_not_found_exception" in str(exc):
            raise HTTPException(
                status_code=404,
                detail="Alert history index does not exist"
            )
        raise

    try:
        existing = es.get(index=INCIDENTS_INDEX, id=alert_id)
        incident = existing["_source"].copy()
        incident["incident_id"] = alert_id
        return {"message": "Incident already exists", "incident": incident}
    except Exception as exc:
        if "index_not_found_exception" not in str(exc) and "not_found" not in str(exc).lower() and "404" not in str(exc):
            raise

    alert = alert_result["_source"]
    now = datetime.now(timezone.utc).isoformat()
    priority = (request.priority or alert.get("severity") or "MEDIUM").strip().upper()
    if priority not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(
            status_code=400,
            detail="priority must be LOW, MEDIUM, HIGH, or CRITICAL"
        )

    incident = {
        "alert_history_id": alert_id,
        "alert": alert.get("alert", "Security Alert"),
        "severity": alert.get("severity", "LOW"),
        "priority": priority,
        "risk_score": alert.get("risk_score", 0),
        "host": alert.get("host", "Unknown host"),
        "source_ip": alert.get("source_ip", ""),
        "username": alert.get("username", ""),
        "event_id": alert.get("event_id", ""),
        "threat_type": alert.get("threat_type", ""),
        "message": alert.get("message", ""),
        "simulation_only": bool(alert.get("simulation_only", False)),
        "assigned_to": (request.assigned_to or "").strip() or None,
        "status": "OPEN",
        "notes": [],
        "created_at": now,
        "updated_at": now
    }

    es.index(
        index=INCIDENTS_INDEX,
        id=alert_id,
        document=incident,
        refresh=True
    )
    incident["incident_id"] = alert_id
    return {"message": "Incident created", "incident": incident}


@app.get("/incidents/{incident_id}", dependencies=[Depends(get_current_user)])
def get_incident(incident_id: str):
    try:
        result = es.get(index=INCIDENTS_INDEX, id=incident_id)
    except Exception as exc:
        if "not_found" in str(exc).lower() or "404" in str(exc):
            raise HTTPException(status_code=404, detail="Incident not found")
        raise

    incident = result["_source"].copy()
    incident["incident_id"] = incident_id
    return incident


@app.patch("/incidents/{incident_id}", dependencies=[Depends(get_current_user)])
def update_incident(incident_id: str, request: UpdateIncidentRequest):
    updates = request.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No incident fields supplied")

    if "status" in updates:
        updates["status"] = (updates["status"] or "").strip().upper()
        if updates["status"] not in {"OPEN", "INVESTIGATING", "RESOLVED"}:
            raise HTTPException(
                status_code=400,
                detail="status must be OPEN, INVESTIGATING, or RESOLVED"
            )

    if "priority" in updates:
        updates["priority"] = (updates["priority"] or "").strip().upper()
        if updates["priority"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(
                status_code=400,
                detail="priority must be LOW, MEDIUM, HIGH, or CRITICAL"
            )

    if "assigned_to" in updates:
        updates["assigned_to"] = (updates["assigned_to"] or "").strip() or None

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        es.update(
            index=INCIDENTS_INDEX,
            id=incident_id,
            doc=updates,
            retry_on_conflict=3,
            refresh=True
        )
    except Exception as exc:
        if "not_found" in str(exc).lower() or "404" in str(exc):
            raise HTTPException(status_code=404, detail="Incident not found")
        raise

    return {
        "message": "Incident updated",
        "incident_id": incident_id,
        "updated_fields": updates
    }


@app.post("/incidents/{incident_id}/notes", dependencies=[Depends(get_current_user)])
def add_incident_note(incident_id: str, request: IncidentNoteRequest):
    note_text = request.note.strip()
    if not note_text:
        raise HTTPException(status_code=400, detail="Note cannot be empty")
    if len(note_text) > 5000:
        raise HTTPException(status_code=400, detail="Note must be 5000 characters or fewer")

    now = datetime.now(timezone.utc).isoformat()
    note = {
        "note": note_text,
        "author": (request.author or "").strip() or "Analyst",
        "created_at": now
    }

    try:
        es.update(
            index=INCIDENTS_INDEX,
            id=incident_id,
            script={
                "lang": "painless",
                "source": """
                    if (ctx._source.notes == null) {
                        ctx._source.notes = [];
                    }
                    ctx._source.notes.add(params.note);
                    ctx._source.updated_at = params.now;
                """,
                "params": {"note": note, "now": now}
            },
            retry_on_conflict=3,
            refresh=True
        )
    except Exception as exc:
        if "not_found" in str(exc).lower() or "404" in str(exc):
            raise HTTPException(status_code=404, detail="Incident not found")
        raise

    return {
        "message": "Investigation note added",
        "incident_id": incident_id,
        "note": note
    }


# --------------------------------------------------
# REAL-TIME WEBSOCKET
# --------------------------------------------------

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008, reason="Authentication required")
        return

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        username = payload.get("sub")
        if not username or username != ADMIN_USERNAME:
            await websocket.close(code=1008, reason="Invalid authentication token")
            return
    except jwt.InvalidTokenError:
        await websocket.close(code=1008, reason="Invalid or expired authentication token")
        return

    await websocket.accept()
    print(f"Authenticated WebSocket client connected: {username}")

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
                await websocket.send_json({
                    "events": [],
                    "error": "Unable to retrieve events from Elasticsearch"
                })
                await asyncio.sleep(3)

    except Exception as exc:
        print("WebSocket disconnected:", repr(exc))