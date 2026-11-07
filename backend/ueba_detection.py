from collections import Counter
from datetime import datetime


def detect_anomalous_behavior(events, behavior_baseline=None):

    # ==========================================
    # CURRENT ACTIVITY COUNTERS
    # ==========================================

    user_activity = Counter()
    user_failed_logins = Counter()
    user_unusual_hour_activity = Counter()

    ip_activity = Counter()
    ip_failed_logins = Counter()
    ip_unusual_hour_activity = Counter()

    # User -> IP relationship activity
    user_ip_activity = {}

    # ==========================================
    # PROCESS EVENTS
    # ==========================================

    for event in events:

        username = event.get("username")
        source_ip = event.get("source_ip")
        raw_event_type = event.get("event_type") or []
        event_types = (
            {str(item).strip().lower() for item in raw_event_type}
            if isinstance(raw_event_type, list)
            else {str(raw_event_type).strip().lower()}
        )
        event_types.discard("")
        event_type = (
            "login_failed" if "login_failed" in event_types
            else "login_success" if "login_success" in event_types
            else next(iter(event_types), "")
        )
        timestamp = event.get("@timestamp")

        event_hour = None

        if timestamp:
            try:
                event_time = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
                event_hour = event_time.hour

            except (ValueError, TypeError):
                event_hour = None

        # ==========================================
        # USER ACTIVITY
        # ==========================================

        if username:

            user_activity[username] += 1

            if event_type == "login_failed":
                user_failed_logins[username] += 1

            if event_hour is not None:

                if event_hour < 6 or event_hour >= 22:
                    user_unusual_hour_activity[username] += 1

        # ==========================================
        # IP ACTIVITY
        # ==========================================

        if source_ip:

            ip_activity[source_ip] += 1

            if event_type == "login_failed":
                ip_failed_logins[source_ip] += 1

            if event_hour is not None:

                if event_hour < 6 or event_hour >= 22:
                    ip_unusual_hour_activity[source_ip] += 1

        # ==========================================
        # USER -> IP RELATIONSHIP
        # ==========================================

        if username and source_ip:

            if username not in user_ip_activity:
                user_ip_activity[username] = Counter()

            user_ip_activity[username][source_ip] += 1

    # ==========================================
    # LOAD HISTORICAL BASELINE
    # ==========================================

    previous_user_baseline = {}
    previous_ip_baseline = {}
    previous_user_ip_baseline = {}

    if behavior_baseline:

        previous_user_baseline = behavior_baseline.get(
            "user_baseline",
            {}
        )

        previous_ip_baseline = behavior_baseline.get(
            "ip_baseline",
            {}
        )

        previous_user_ip_baseline = behavior_baseline.get(
            "user_ip_baseline",
            {}
        )

    # ==========================================
    # STORE ANOMALIES
    # ==========================================

    anomalies = {}

    # ==========================================
    # ENTITY ANALYSIS FUNCTION
    # ==========================================

    def analyze_entity(
        entity,
        entity_type,
        activity_count,
        failed_count,
        unusual_hour_count,
        baseline_count
    ):

        # ------------------------------------------
        # DETECTION CONDITIONS
        # ------------------------------------------

        high_activity = activity_count > 10

        excessive_failed_logins = failed_count >= 5

        baseline_anomaly = (
            baseline_count > 0
            and activity_count > baseline_count * 2
        )

        unusual_hour_anomaly = unusual_hour_count >= 3

        # No anomaly
        # High event volume by itself is not enough to call an entity
        # suspicious. Windows events such as 4798 can be generated routinely.
        # Require an independent signal before high volume contributes to an
        # anomaly; failed-login, baseline-deviation and unusual-hour signals
        # can still trigger detection on their own.
        high_activity_with_signal = (
            high_activity
            and (failed_count > 0 or unusual_hour_count > 0 or baseline_anomaly)
        )

        if not (
            excessive_failed_logins
            or baseline_anomaly
            or unusual_hour_anomaly
            or high_activity_with_signal
        ):
            return None

        # ------------------------------------------
        # RISK SCORE
        # ------------------------------------------

        risk_score = 0

        risk_factors = []

        if high_activity:

            risk_score += 20

            risk_factors.append(
                "High Activity Volume"
            )

        if excessive_failed_logins:

            risk_score += 30

            risk_factors.append(
                "Excessive Failed Logins"
            )

        if baseline_anomaly:

            risk_score += 25

            risk_factors.append(
                "Activity Exceeded Historical Baseline"
            )

        if unusual_hour_anomaly:

            risk_score += 20

            risk_factors.append(
                "Activity Detected During Unusual Hours"
            )

        risk_score = min(
            risk_score,
            100
        )

        # ------------------------------------------
        # ANOMALY TYPE
        # ------------------------------------------

        factor_count = len(
            risk_factors
        )

        if factor_count >= 3:

            anomaly_type = (
                "Multi-Factor UEBA Anomaly"
            )

        elif excessive_failed_logins:

            anomaly_type = (
                "Excessive Failed Login Activity"
            )

        elif baseline_anomaly:

            anomaly_type = (
                "Behavior Deviation From Baseline"
            )

        elif unusual_hour_anomaly:

            anomaly_type = (
                "Unusual Time-Based Behavior"
            )

        else:

            anomaly_type = (
                "Unusual User/Entity Behavior"
            )

        # ------------------------------------------
        # DETECTION REASON
        # ------------------------------------------

        detection_reason = " + ".join(
            risk_factors
        )

        # ------------------------------------------
        # SEVERITY
        # ------------------------------------------

        if risk_score >= 80:

            severity = "CRITICAL"

        elif risk_score >= 60:

            severity = "HIGH"

        elif risk_score >= 30:

            severity = "MEDIUM"

        else:

            severity = "LOW"

        # ------------------------------------------
        # RESULT
        # ------------------------------------------

        return {

            "entity": entity,
            "username": entity if entity_type == "USER" else None,
            "source_ip": entity if entity_type == "IP" else None,

            "entity_type": entity_type,

            "activity_count": activity_count,

            "failed_login_count": failed_count,

            "unusual_hour_activity": unusual_hour_count,

            "baseline_activity": baseline_count,

            "anomaly_type": anomaly_type,

            "detection_reason": detection_reason,

            "risk_score": risk_score,

            "severity": severity
        }

    # ==========================================
    # USER UEBA ANALYSIS
    # ==========================================

    for username, activity_count in user_activity.items():

        failed_count = user_failed_logins.get(
            username,
            0
        )

        unusual_hour_count = user_unusual_hour_activity.get(
            username,
            0
        )

        baseline_count = previous_user_baseline.get(
            username,
            0
        )

        result = analyze_entity(

            username,

            "USER",

            activity_count,

            failed_count,

            unusual_hour_count,

            baseline_count
        )

        if result:

            anomalies[
                f"user:{username}"
            ] = result

    # ==========================================
    # IP UEBA ANALYSIS
    # ==========================================

    for source_ip, activity_count in ip_activity.items():

        failed_count = ip_failed_logins.get(
            source_ip,
            0
        )

        unusual_hour_count = ip_unusual_hour_activity.get(
            source_ip,
            0
        )

        baseline_count = previous_ip_baseline.get(
            source_ip,
            0
        )

        result = analyze_entity(

            source_ip,

            "IP",

            activity_count,

            failed_count,

            unusual_hour_count,

            baseline_count
        )

        if result:

            anomalies[
                f"ip:{source_ip}"
            ] = result

    # ==========================================
    # USER -> IP RELATIONSHIP ANALYSIS
    # ==========================================

    for username, ip_counter in user_ip_activity.items():

        historical_relationships = (
            previous_user_ip_baseline.get(
                username,
                {}
            )
        )

        # If we have never seen this user before,
        # we cannot determine a new relationship.
        if not historical_relationships:

            continue

        for source_ip, relationship_count in ip_counter.items():

            # --------------------------------------
            # NEW USER -> IP RELATIONSHIP
            # --------------------------------------

            if source_ip not in historical_relationships:

                risk_score = 25

                risk_factors = [
                    "New User-IP Relationship"
                ]

                # ----------------------------------
                # ADD USER BEHAVIOR FACTORS
                # ----------------------------------

                total_user_activity = user_activity.get(
                    username,
                    0
                )

                user_failed_count = user_failed_logins.get(
                    username,
                    0
                )

                user_unusual_hours = user_unusual_hour_activity.get(
                    username,
                    0
                )

                user_baseline = previous_user_baseline.get(
                    username,
                    0
                )

                # High activity
                if total_user_activity > 10:

                    risk_score += 20

                    risk_factors.append(
                        "High Activity Volume"
                    )

                # Excessive failed logins
                if user_failed_count >= 5:

                    risk_score += 30

                    risk_factors.append(
                        "Excessive Failed Logins"
                    )

                # Baseline deviation
                if (
                    user_baseline > 0
                    and total_user_activity
                    > user_baseline * 2
                ):

                    risk_score += 25

                    risk_factors.append(
                        "Activity Exceeded Historical Baseline"
                    )

                # Unusual hours
                if user_unusual_hours >= 3:

                    risk_score += 20

                    risk_factors.append(
                        "Activity Detected During Unusual Hours"
                    )

                # Maximum risk
                risk_score = min(
                    risk_score,
                    100
                )

                # ----------------------------------
                # ANOMALY TYPE
                # ----------------------------------

                if len(risk_factors) >= 3:

                    anomaly_type = (
                        "Multi-Factor UEBA Anomaly"
                    )

                else:

                    anomaly_type = (
                        "Unusual User-IP Relationship"
                    )

                # ----------------------------------
                # SEVERITY
                # ----------------------------------

                if risk_score >= 80:

                    severity = "CRITICAL"

                elif risk_score >= 60:

                    severity = "HIGH"

                elif risk_score >= 30:

                    severity = "MEDIUM"

                else:

                    severity = "LOW"

                # ----------------------------------
                # DETECTION REASON
                # ----------------------------------

                detection_reason = " + ".join(
                    risk_factors
                )

                # ----------------------------------
                # KNOWN IPs
                # ----------------------------------

                known_source_ips = list(
                    historical_relationships.keys()
                )

                # ----------------------------------
                # STORE RELATIONSHIP ANOMALY
                # ----------------------------------

                relationship_key = (
                    f"user_ip:{username}:{source_ip}"
                )

                anomalies[
                    relationship_key
                ] = {

                    "entity": username,

                    "entity_type":
                        "USER_IP_RELATIONSHIP",

                    "username":
                        username,

                    "source_ip":
                        source_ip,

                    "relationship_activity_count":
                        relationship_count,

                    "activity_count":
                        total_user_activity,

                    "failed_login_count":
                        user_failed_count,

                    "unusual_hour_activity":
                        user_unusual_hours,

                    "baseline_activity":
                        user_baseline,

                    "known_source_ips":
                        known_source_ips,

                    "anomaly_type":
                        anomaly_type,

                    "detection_reason":
                        detection_reason,

                    "risk_score":
                        risk_score,

                    "severity":
                        severity
                }

    # ==========================================
    # RETURN ALL ANOMALIES
    # ==========================================

    return anomalies