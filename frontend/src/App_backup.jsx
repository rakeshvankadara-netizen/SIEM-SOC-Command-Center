import { Fragment, useEffect, useRef, useState } from "react";
import "./App.css";
import Network3D from "./Network3D";

const API_URL = "http://127.0.0.1:8001";

function App() {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [alertHistory, setAlertHistory] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsError, setIncidentsError] = useState("");
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [incidentNoteDrafts, setIncidentNoteDrafts] = useState({});
  const [incidentBusyId, setIncidentBusyId] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [historyStatusFilter, setHistoryStatusFilter] = useState("ALL");
  const [historySeverityFilter, setHistorySeverityFilter] = useState("ALL");
  const [historySearch, setHistorySearch] = useState("");
  const [updatingAlertId, setUpdatingAlertId] = useState(null);
  const [ipMonitoring, setIpMonitoring] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [hosts, setHosts] = useState([]);

  const [searchTerm, setSearchTerm] = useState("");
  const searchTermRef = useRef("");
  searchTermRef.current = searchTerm;
  const [currentTime, setCurrentTime] = useState(new Date());

  const [investigating, setInvestigating] = useState(false);

  const [loading, setLoading] = useState(true);
  const [alertsLoading, setAlertsLoading] = useState(true);
  const [ipLoading, setIpLoading] = useState(true);
  const [analyticsLoading, setAnalyticsLoading] = useState(true);

  const [error, setError] = useState("");
  const [alertsError, setAlertsError] = useState("");
  const [ipError, setIpError] = useState("");
  const [analyticsError, setAnalyticsError] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [activeSection, setActiveSection] = useState(() => window.location.hash.slice(1) || "dashboard");


  // --------------------------------------------------
  // FETCH SECURITY EVENTS
  // --------------------------------------------------

  const fetchEvents = async (eventId = null) => {

    try {

      setLoading(true);
      setError("");

      const params = new URLSearchParams({ limit: "500" });

      // If the search is a numeric Windows Event ID, request matching
      // events from the backend instead of searching only loaded events.
      if (eventId && /^\d+$/.test(eventId.trim())) {
        params.set("event_id", eventId.trim());
      }

      const response = await fetch(
        `${API_URL}/events?${params.toString()}`
      );

      if (!response.ok) {
        throw new Error("Failed to fetch events");
      }

      const data = await response.json();

      setEvents(data.events || []);

    } catch (err) {

      setError(
        "Unable to connect to SIEM backend"
      );

    } finally {

      setLoading(false);

    }

  };


  // --------------------------------------------------
  // FETCH SECURITY ALERTS
  // --------------------------------------------------

  const fetchAlerts = async () => {

    try {

      setAlertsLoading(true);
      setAlertsError("");

      const response = await fetch(
        `${API_URL}/alerts`
      );

      if (!response.ok) {
        throw new Error("Failed to fetch alerts");
      }

      const data = await response.json();

      setAlerts(data.alerts || []);

    } catch (err) {

      setAlertsError(
        "Unable to load security alerts"
      );

    } finally {

      setAlertsLoading(false);

    }

  };


  // --------------------------------------------------
  // ALERT HISTORY AND STATUS MANAGEMENT
  // --------------------------------------------------

  const fetchAlertHistory = async () => {
    try {
      setHistoryLoading(true);
      setHistoryError("");
      const response = await fetch(`${API_URL}/alert-history?limit=100`);
      if (!response.ok) throw new Error("Failed to fetch alert history");
      const data = await response.json();
      setAlertHistory(data.alerts || []);
    } catch (err) {
      setHistoryError("Unable to load alert history. Check that the backend is running.");
    } finally {
      setHistoryLoading(false);
    }
  };

  const updateAlertStatus = async (alert, status) => {
    const alertId = alert.history_id || alert.alert_id || alert.id;
    if (!alertId) {
      setHistoryError("This alert does not contain a history ID, so its status cannot be updated.");
      return;
    }

    try {
      setUpdatingAlertId(alertId);
      setHistoryError("");
      const response = await fetch(
        `${API_URL}/alert-history/${encodeURIComponent(alertId)}/status?status=${encodeURIComponent(status)}`,
        { method: "PATCH", headers: { Accept: "application/json" } }
      );
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Status update failed");
      }
      await fetchAlertHistory();
      await fetchAlerts();
    } catch (err) {
      setHistoryError(`Could not update alert status: ${err.message}`);
    } finally {
      setUpdatingAlertId(null);
    }
  };

  // --------------------------------------------------
  // INCIDENT MANAGEMENT
  // --------------------------------------------------

  const fetchIncidents = async () => {
    try {
      setIncidentsLoading(true);
      setIncidentsError("");
      const response = await fetch(`${API_URL}/incidents`);
      if (!response.ok) throw new Error("Failed to fetch incidents");
      const data = await response.json();
      setIncidents(data.incidents || []);
    } catch (err) {
      setIncidentsError(`Unable to load incidents: ${err.message}`);
    } finally {
      setIncidentsLoading(false);
    }
  };

  const createIncident = async (alert) => {
    const alertId = alert.history_id || alert.alert_history_id || alert.alert_id || alert.id;
    if (!alertId) {
      setIncidentsError("This alert has no history ID and cannot be converted into an incident.");
      return;
    }
    try {
      setIncidentBusyId(alertId);
      setIncidentsError("");
      const response = await fetch(`${API_URL}/incidents`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({
          alert_history_id: alertId,
          assigned_to: "Unassigned",
          priority: alert.severity || "MEDIUM"
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Incident creation failed");
      await fetchIncidents();
      window.alert(data.message || "Incident created successfully.");
    } catch (err) {
      setIncidentsError(err.message);
    } finally {
      setIncidentBusyId(null);
    }
  };

  const updateIncident = async (incident, changes) => {
    const id = incident.incident_id;
    try {
      setIncidentBusyId(id);
      setIncidentsError("");
      const response = await fetch(`${API_URL}/incidents/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(changes)
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Incident update failed");
      await fetchIncidents();
    } catch (err) {
      setIncidentsError(err.message);
    } finally {
      setIncidentBusyId(null);
    }
  };

  const addIncidentNote = async (incident) => {
    const id = incident.incident_id;
    const note = (incidentNoteDrafts[id] || "").trim();
    if (!note) {
      setIncidentsError("Enter an investigation note before submitting.");
      return;
    }
    try {
      setIncidentBusyId(id);
      setIncidentsError("");
      const response = await fetch(`${API_URL}/incidents/${encodeURIComponent(id)}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ note, author: "Security Analyst" })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Could not add investigation note");
      setIncidentNoteDrafts((current) => ({ ...current, [id]: "" }));
      await fetchIncidents();
    } catch (err) {
      setIncidentsError(err.message);
    } finally {
      setIncidentBusyId(null);
    }
  };

  // --------------------------------------------------
  // FETCH IP MONITORING
  // --------------------------------------------------

  const fetchIPMonitoring = async () => {

    try {

      setIpLoading(true);
      setIpError("");

      const response = await fetch(
        `${API_URL}/ip-monitoring`
      );

      if (!response.ok) {
        throw new Error(
          "Failed to fetch IP monitoring"
        );
      }

      const data = await response.json();

      setIpMonitoring(data.ips || []);

    } catch (err) {

      setIpError(
        "Unable to load IP monitoring data"
      );

    } finally {

      setIpLoading(false);

    }

  };


  // --------------------------------------------------
  // FETCH SECURITY ANALYTICS
  // --------------------------------------------------

  const fetchAnalytics = async () => {

    try {

      setAnalyticsLoading(true);
      setAnalyticsError("");

      const response = await fetch(
        `${API_URL}/analytics`
      );

      if (!response.ok) {
        throw new Error(
          "Failed to fetch analytics"
        );
      }

      const data = await response.json();

      setAnalytics(data);

    } catch (err) {

      setAnalyticsError(
        "Unable to load security analytics"
      );

    } finally {

      setAnalyticsLoading(false);

    }

  };


  // --------------------------------------------------
  // FETCH MONITORED HOSTS
  // --------------------------------------------------

  const fetchHosts = async () => {

    try {

      const response = await fetch(
        `${API_URL}/hosts`
      );

      if (!response.ok) {
        throw new Error("Failed to fetch monitored hosts");
      }

      const data = await response.json();

      setHosts(data.hosts || []);

    } catch (err) {

      console.error(
        "Failed to fetch monitored hosts:",
        err
      );

    }

  };


  // --------------------------------------------------
  // THREAT INVESTIGATION
  // --------------------------------------------------

  const investigateIP = async (sourceIP) => {

    try {

      setInvestigating(true);
      setInvestigation(null);

      const response = await fetch(
        `${API_URL}/investigate/${sourceIP}`
      );

      if (!response.ok) {
        throw new Error(
          "Investigation failed"
        );
      }

      const data = await response.json();

      setInvestigation(data);

    } catch (err) {

      console.error(
        "Investigation failed:",
        err
      );

    } finally {

      setInvestigating(false);

    }

  };


  // --------------------------------------------------
  // LIVE CLOCK
  // --------------------------------------------------

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  // Keep the sidebar highlight synchronized with the current hash section.
  useEffect(() => {
    const updateActiveSection = () => {
      setActiveSection(window.location.hash.slice(1) || "dashboard");
    };
    window.addEventListener("hashchange", updateActiveSection);
    return () => window.removeEventListener("hashchange", updateActiveSection);
  }, []);


  // --------------------------------------------------
  // INITIAL LOAD
  // --------------------------------------------------

  useEffect(() => {

    fetchEvents();
    fetchAlerts();
    fetchAlertHistory();
    fetchIncidents();
    fetchIPMonitoring();
    fetchAnalytics();
    fetchHosts();


    // Refresh alert data at a controlled interval, not on every
    // WebSocket message. The backend uses stable alert IDs to update
    // existing history records and preserve their statuses.
    let lastAlertRefresh = Date.now();

    const socket = new WebSocket(
      "ws://127.0.0.1:8001/ws/events"
    );


    socket.onopen = () => {

      console.log(
        "WebSocket connected"
      );

    };


    socket.onmessage = (message) => {

      const data = JSON.parse(
        message.data
      );

      if (data.events) {
        // Keep backend-filtered Event ID results visible while a numeric
        // search is active; otherwise the live WebSocket would overwrite them.
        const activeSearch = searchTermRef.current.trim();
        if (!/^\d+$/.test(activeSearch)) {
          setEvents(data.events);
        }

        setLoading(false);
        setError("");
        fetchHosts();

        // Refresh active alerts and persistent history every 10 seconds.
        if (Date.now() - lastAlertRefresh >= 10000) {
          lastAlertRefresh = Date.now();
          fetchAlerts();
          fetchAlertHistory();
          fetchIncidents();
        }
      }

    };


    socket.onerror = () => {

      console.error(
        "WebSocket connection failed"
      );

      setError(
        "WebSocket connection failed"
      );

    };


    socket.onclose = () => {

      console.log(
        "WebSocket disconnected"
      );

    };


    return () => {

      socket.close();

    };

  }, []);


  // --------------------------------------------------
  // STATISTICS
  // --------------------------------------------------

  const totalEvents = events.length;


  const threatsDetected = events.filter(
    (event) => event.threat_type
  ).length;


  const failedLogins = events.filter((event) => {
    const eventType = Array.isArray(event.event_type)
      ? event.event_type.join(" ").toLowerCase()
      : String(event.event_type || "").toLowerCase();

    const eventId = String(
      event.winlog?.event_id ??
      event.event?.code ??
      event.event_id ??
      ""
    );

    return (
      eventType.includes("login_failed") ||
      eventType.includes("login-failed") ||
      eventId === "4625"
    );
  }).length;


  const highSeverityAlerts = events.filter(
    (event) =>
      event.severity === "HIGH" ||
      event.severity === "CRITICAL"
  ).length;

  // --------------------------------------------------
  // SOC THREAT LEVEL
  // --------------------------------------------------

  const criticalThreats = alerts.filter(
    (alert) => alert.severity === "CRITICAL"
  ).length;

  const highThreats = alerts.filter(
    (alert) => alert.severity === "HIGH"
  ).length;

  const mediumThreats = alerts.filter(
    (alert) => alert.severity === "MEDIUM"
  ).length;

  const lowThreats = alerts.filter(
    (alert) => alert.severity === "LOW"
  ).length;

  // UEBA anomalies are generated by the backend and included in /alerts.
  const uebaAlerts = alerts.filter((alert) =>
    String(alert.alert || "").toLowerCase().includes("ueba") ||
    Boolean(alert.entity_type)
  );
  const uebaSeverityCounts = {
    critical: uebaAlerts.filter((alert) => alert.severity === "CRITICAL").length,
    high: uebaAlerts.filter((alert) => alert.severity === "HIGH").length,
    medium: uebaAlerts.filter((alert) => alert.severity === "MEDIUM").length,
    low: uebaAlerts.filter((alert) => alert.severity === "LOW").length,
  };
  const uebaEntities = new Set(
    uebaAlerts.map((alert) => alert.username || alert.source_ip || "Unknown")
  ).size;

  const threatScore = Math.min(
    100,
    criticalThreats * 25 +
      highThreats * 10 +
      mediumThreats * 5 +
      lowThreats * 2
  );

  const threatLevel =
    threatScore >= 75
      ? "CRITICAL"
      : threatScore >= 50
        ? "HIGH"
        : threatScore >= 25
          ? "MEDIUM"
          : "LOW";

  const normalizedSearch = searchTerm.trim().toLowerCase();

  const filteredEvents = normalizedSearch
    ? events.filter((event) => {
        const eventId = String(
          event.winlog?.event_id ??
          event.event?.code ??
          event.event_id ??
          ""
        ).toLowerCase();

        return (
          eventId.includes(normalizedSearch) ||
          JSON.stringify(event).toLowerCase().includes(normalizedSearch)
        );
      })
    : events;

  // Numeric searches such as 4625 query the backend directly.
  useEffect(() => {
    const term = searchTerm.trim();

    if (term === "") {
      fetchEvents();
      return;
    }

    if (!/^\d+$/.test(term)) {
      return;
    }

    const timer = setTimeout(() => {
      fetchEvents(term);
    }, 300);

    return () => clearTimeout(timer);
  }, [searchTerm]);

  const liveTime = currentTime.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  // --------------------------------------------------
  // EVENT DISPLAY HELPERS
  // --------------------------------------------------

  const getEventUsername = (event) =>
    event.username ||
    event.user?.name ||
    event.winlog?.event_data?.TargetUserName ||
    event.winlog?.event_data?.SubjectUserName ||
    "-";

  const getEventHost = (event) =>
    event.host?.hostname ||
    event.host?.name ||
    event.hostname ||
    "-";

  const getEventId = (event) =>
    event.winlog?.event_id ||
    event.event?.code ||
    event.event_id ||
    "-";

  const getEventSeverity = (event) =>
    event.severity || (event.alert ? "ALERT" : "Normal");

  const getEventTime = (event) =>
    event["@timestamp"]
      ? new Date(event["@timestamp"]).toLocaleTimeString()
      : "-";

  // Elasticsearch may store event_type as an array for Windows events.
  const getEventTypeLabel = (event) => {
    const value = event?.event_type;
    if (Array.isArray(value)) return value.join(" · ");
    return value || "security_event";
  };

  // Make missing and loopback addresses explicit instead of presenting them
  // as if they were remote attacker IPs.
  const formatSourceIP = (value) => {
    if (Array.isArray(value)) value = value[0];
    if (value === null || value === undefined || String(value).trim() === "" || String(value).trim() === "-") {
      return "Unknown";
    }
    const ip = String(value).trim();
    if (ip === "::1" || ip === "127.0.0.1") return `Localhost (${ip})`;
    return ip;
  };

  const topSourceIPs = Array.isArray(analytics?.top_source_ips)
    ? analytics.top_source_ips.filter((item) => item && item.source_ip != null)
    : [];

  const downloadReport = (type) => {
    const rows = type === "alerts" ? alertHistory : events;
    if (!rows.length) {
      window.alert(`No ${type} data is available to export yet.`);
      return;
    }
    const columns = type === "alerts"
      ? ["alert", "severity", "risk_score", "username", "source_ip", "status", "first_seen", "last_seen"]
      : ["@timestamp", "event_type", "event_id", "hostname", "username", "severity", "risk_score", "source_ip", "message"];
    const valueFor = (row, key) => {
      if (key === "event_id") return row.winlog?.event_id ?? row.event?.code ?? row.event_id ?? "";
      if (key === "hostname") return row.host?.hostname ?? row.host?.name ?? row.hostname ?? "";
      if (key === "username") return row.username ?? row.user?.name ?? row.winlog?.event_data?.TargetUserName ?? "";
      if (key === "source_ip") return row.source_ip ?? row.source?.ip ?? "";
      const value = row[key];
      return value == null ? "" : Array.isArray(value) ? value.join("; ") : typeof value === "object" ? JSON.stringify(value) : value;
    };
    const escapeCsv = (value) => `"${String(value).replaceAll('"', '""')}"`;
    const csv = [columns.join(","), ...rows.map((row) => columns.map((key) => escapeCsv(valueFor(row, key))).join(","))].join("\r\n");
    const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `siem-${type}-report-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  return (

    <div className="app">

      {/* ==================================================
          SOC SIDEBAR
      ================================================== */}

      <aside className="soc-sidebar">

        <div className="sidebar-brand">
          <div className="sidebar-logo">🛡️</div>

          <div>
            <h2>SIEM</h2>
            <span>SOC COMMAND CENTER</span>
          </div>
        </div>

        <nav className="sidebar-nav">

          <a href="#dashboard" className={`sidebar-item ${activeSection === "dashboard" ? "active" : ""}`}>
            <span>▣</span>
            Dashboard
          </a>

          <a href="#events" className={`sidebar-item ${activeSection === "events" ? "active" : ""}`}>
            <span>◉</span>
            Live Events
          </a>

          <a href="#alerts" className={`sidebar-item ${activeSection === "alerts" ? "active" : ""}`}>
            <span>⚠</span>
            Security Alerts
          </a>

          <a href="#alert-management" className={`sidebar-item ${activeSection === "alert-management" ? "active" : ""}`}>
            <span>☑</span>
            Alert Management
          </a>
          <a href="#incidents" className={`sidebar-item ${activeSection === "incidents" ? "active" : ""}`}>
            <span>🧾</span>
            Incident Management
          </a>

          <a href="#hosts" className={`sidebar-item ${activeSection === "hosts" ? "active" : ""}`}>
            <span>▣</span>
            Host Monitoring
          </a>

          <a href="#threat-intelligence" className={`sidebar-item ${activeSection === "threat-intelligence" ? "active" : ""}`}>
            <span>◉</span>
            Threat Intelligence
          </a>

          <a href="#ueba" className={`sidebar-item ${activeSection === "ueba" ? "active" : ""}`}>
            <span>◈</span>
            UEBA Analysis
          </a>

          <a href="#network" className={`sidebar-item ${activeSection === "network" ? "active" : ""}`}>
            <span>⌘</span>
            Network Topology
          </a>

          <a href="#investigation" className={`sidebar-item ${activeSection === "investigation" ? "active" : ""}`}>
            <span>⌕</span>
            Investigation
          </a>

          <a href="#reports" className={`sidebar-item ${activeSection === "reports" ? "active" : ""}`}>
            <span>▤</span>
            Reports
          </a>

          <a href="#settings" className={`sidebar-item ${activeSection === "settings" ? "active" : ""}`}>
            <span>⚙</span>
            Settings
          </a>

        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-status-dot"></div>

          <div>
            <strong>SIEM v1.0</strong>
            <span>Security Operations Center</span>
          </div>
        </div>

      </aside>


      {/* ==================================================
          SOC COMMAND CENTER TOP BAR
      ================================================== */}

      <header className="topbar">

        <div className="topbar-brand">

          <div className="topbar-title-row">

            <span className="topbar-shield">🛡️</span>

            <div>
              <h1>SIEM SOC COMMAND CENTER</h1>

              <p>
                Real-Time Security Monitoring & Threat Detection
              </p>
            </div>

          </div>

        </div>


        <div className="topbar-actions">

          <div className="global-search">

            <span className="search-icon">⌕</span>

            <input
              type="text"
              placeholder="Search IP, Host, Event, User..."
              value={searchTerm}
              onChange={(event) =>
                setSearchTerm(event.target.value)
              }
            />

            {searchTerm && (
              <button
                className="search-clear"
                onClick={() => setSearchTerm("")}
                aria-label="Clear search"
              >
                ×
              </button>
            )}

          </div>


          <div className="live-clock">

            <span className="clock-icon">◷</span>

            <div>
              <strong>{liveTime}</strong>
              <span>LIVE</span>
            </div>

          </div>


          <div className="status">

            <span className="dot"></span>

            <div>
              <strong>SYSTEM ONLINE</strong>
              <span>All Services Running</span>
            </div>

          </div>

        </div>

      </header>


      <main className="dashboard" id="dashboard">


        {/* ==================================================
            STATISTICS
        ================================================== */}

        <section className="stats">


          <div className="card">

            <h3>
              Total Events
            </h3>

            <strong>
              {totalEvents}
            </strong>

            <span>
              Security events received
            </span>

          </div>


          <div className="card danger">

            <h3>
              Threats Detected
            </h3>

            <strong>
              {threatsDetected}
            </strong>

            <span>
              Potential threats detected
            </span>

          </div>


          <div className="card warning">

            <h3>
              Failed Logins
            </h3>

            <strong>
              {failedLogins}
            </strong>

            <span>
              Authentication failures
            </span>

          </div>


          <div className="card danger">

            <h3>
              High Severity Alerts
            </h3>

            <strong>
              {highSeverityAlerts}
            </strong>

            <span>
              Critical security alerts
            </span>

          </div>


        </section>


        {/* ==================================================
            SOC THREAT LEVEL
        ================================================== */}

        <section
          className={`threat-level-panel threat-${threatLevel.toLowerCase()}`}
          style={{
            marginBottom: "28px",
            padding: "24px",
            background: "linear-gradient(135deg, #0f1b31 0%, #0a1324 100%)",
            border: "1px solid #243b5a",
            borderRadius: "16px",
            boxShadow: "0 10px 35px rgba(0, 0, 0, 0.25)",
          }}
        >
          <div
            className="threat-level-header"
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              gap: "20px",
              marginBottom: "22px",
            }}
          >
            <div>
              <h2
                style={{
                  margin: 0,
                  color: "#f8fafc",
                  fontSize: "22px",
                  fontWeight: 800,
                }}
              >
                🛡️ Threat Level
              </h2>
              <p
                style={{
                  margin: "7px 0 0",
                  color: "#94a3b8",
                  fontSize: "14px",
                }}
              >
                Real-time security risk based on active alerts
              </p>
            </div>

            <div
              className="threat-level-status"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "8px",
                padding: "8px 14px",
                borderRadius: "999px",
                background: "rgba(34, 197, 94, 0.10)",
                border: "1px solid rgba(34, 197, 94, 0.30)",
                color: "#4ade80",
                fontWeight: 800,
                fontSize: "13px",
              }}
            >
              <span
                className="threat-status-dot"
                style={{
                  width: "9px",
                  height: "9px",
                  borderRadius: "50%",
                  background:
                    threatLevel === "CRITICAL"
                      ? "#ef4444"
                      : threatLevel === "HIGH"
                        ? "#f97316"
                        : threatLevel === "MEDIUM"
                          ? "#eab308"
                          : "#22c55e",
                  boxShadow:
                    threatLevel === "CRITICAL"
                      ? "0 0 12px #ef4444"
                      : threatLevel === "HIGH"
                        ? "0 0 12px #f97316"
                        : threatLevel === "MEDIUM"
                          ? "0 0 12px #eab308"
                          : "0 0 12px #22c55e",
                }}
              ></span>
              {threatLevel}
            </div>
          </div>

          <div
            className="threat-level-content"
            style={{
              display: "grid",
              gridTemplateColumns: "minmax(220px, 0.8fr) minmax(280px, 1.2fr)",
              alignItems: "center",
              gap: "36px",
            }}
          >
            <div
              className="threat-gauge"
              style={{
                width: "190px",
                height: "190px",
                margin: "0 auto",
                borderRadius: "50%",
                display: "grid",
                placeItems: "center",
                position: "relative",
                background: `conic-gradient(
                  ${
                    threatLevel === "CRITICAL"
                      ? "#ef4444"
                      : threatLevel === "HIGH"
                        ? "#f97316"
                        : threatLevel === "MEDIUM"
                          ? "#eab308"
                          : "#22c55e"
                  } ${Math.max(threatScore, 4)}%,
                  #1e293b ${Math.max(threatScore, 4)}%
                )`,
                boxShadow: `0 0 35px ${
                  threatLevel === "CRITICAL"
                    ? "rgba(239,68,68,0.28)"
                    : threatLevel === "HIGH"
                      ? "rgba(249,115,22,0.25)"
                      : threatLevel === "MEDIUM"
                        ? "rgba(234,179,8,0.22)"
                        : "rgba(34,197,94,0.20)"
                }`,
              }}
            >
              <div
                className="threat-gauge-inner"
                style={{
                  width: "146px",
                  height: "146px",
                  borderRadius: "50%",
                  background: "#0a1324",
                  border: "1px solid #263a56",
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "center",
                  alignItems: "center",
                  position: "relative",
                }}
              >
                <strong
                  style={{
                    fontSize: "42px",
                    lineHeight: 1,
                    color: "#f8fafc",
                    fontWeight: 900,
                  }}
                >
                  {threatScore}
                </strong>
                <span
                  style={{
                    marginTop: "5px",
                    color: "#64748b",
                    fontSize: "13px",
                  }}
                >
                  / 100
                </span>
                <small
                  style={{
                    marginTop: "8px",
                    color:
                      threatLevel === "CRITICAL"
                        ? "#ef4444"
                        : threatLevel === "HIGH"
                          ? "#f97316"
                          : threatLevel === "MEDIUM"
                            ? "#eab308"
                            : "#22c55e",
                    fontSize: "13px",
                    fontWeight: 900,
                    letterSpacing: "1px",
                  }}
                >
                  {threatLevel}
                </small>
              </div>
            </div>

            <div
              className="threat-breakdown"
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "14px",
              }}
            >
              {[
                {
                  name: "Critical",
                  count: criticalThreats,
                  color: "#ef4444",
                  bg: "rgba(239,68,68,0.10)",
                },
                {
                  name: "High",
                  count: highThreats,
                  color: "#f97316",
                  bg: "rgba(249,115,22,0.10)",
                },
                {
                  name: "Medium",
                  count: mediumThreats,
                  color: "#eab308",
                  bg: "rgba(234,179,8,0.10)",
                },
                {
                  name: "Low",
                  count: lowThreats,
                  color: "#22c55e",
                  bg: "rgba(34,197,94,0.10)",
                },
              ].map((item) => (
                <div
                  key={item.name}
                  className={`threat-breakdown-item ${item.name.toLowerCase()}`}
                  style={{
                    minHeight: "82px",
                    padding: "15px",
                    display: "flex",
                    alignItems: "center",
                    gap: "12px",
                    background: item.bg,
                    border: `1px solid ${item.color}33`,
                    borderRadius: "12px",
                  }}
                >
                  <span
                    className="threat-indicator"
                    style={{
                      width: "11px",
                      height: "11px",
                      flexShrink: 0,
                      borderRadius: "50%",
                      background: item.color,
                      boxShadow: `0 0 10px ${item.color}`,
                    }}
                  ></span>

                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "3px",
                    }}
                  >
                    <strong
                      style={{
                        color: "#f8fafc",
                        fontSize: "25px",
                        lineHeight: 1,
                      }}
                    >
                      {item.count}
                    </strong>
                    <span
                      style={{
                        color: "#94a3b8",
                        fontSize: "13px",
                      }}
                    >
                      {item.name}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>



        {/* ==================================================
            3D NETWORK VISUALIZATION
        ================================================== */}

        <section className="panel" id="network">

          <div className="panel-header">

            <div>

              <h2>
                🌐 3D Network Topology
              </h2>

              <p>
                Real-time monitored host network visualization
              </p>

            </div>

          </div>

          <Network3D />

        </section>


        {/* ==================================================
            MONITORED HOSTS
        ================================================== */}

        <section className="panel" id="hosts">

          <div className="panel-header">

            <div>

              <h2>
                💻 Monitored Hosts
              </h2>

              <p>
                Hosts sending security logs to the SIEM
              </p>

            </div>

            <button
              onClick={fetchHosts}
            >
              Refresh Hosts
            </button>

          </div>

          <div className="stats">

            <div className="card">
              <h3>
                Total Hosts
              </h3>

              <strong>
                {hosts.length}
              </strong>

              <span>
                Connected monitored systems
              </span>
            </div>

            {hosts.map((host) => (

              <div
                className="card"
                key={host.hostname}
              >

                <h3>
                  🖥️ {host.hostname}
                </h3>

                <strong>
                  {host.event_count}
                </strong>

                <span>
                  Security events received
                </span>

              </div>

            ))}

          </div>

        </section>


        {/* ==================================================
            SECURITY ANALYTICS
        ================================================== */}

        <section className="panel">

          <div className="panel-header">

            <div>

              <h2>
                📊 Security Analytics
              </h2>

              <p>
                Security activity from the last 5 minutes
              </p>

            </div>


            <button
              onClick={fetchAnalytics}
            >
              Refresh Analytics
            </button>

          </div>


          {analyticsLoading && (

            <p
              style={{
                padding: "20px"
              }}
            >
              Loading security analytics...
            </p>

          )}


          {analyticsError && (

            <p
              style={{
                padding: "20px",
                color: "#f87171"
              }}
            >
              {analyticsError}
            </p>

          )}


          {!analyticsLoading &&
            !analyticsError &&
            analytics && (

            <>


              {/* ------------------------------------------
                  ANALYTICS SUMMARY CARDS
              ------------------------------------------ */}

              <div className="stats">


                <div className="card">

                  <h3>
                    Total Events
                  </h3>

                  <strong>
                    {analytics.total_events}
                  </strong>

                  <span>
                    Last 5 minutes
                  </span>

                </div>


                <div className="card warning">

                  <h3>
                    Failed Logins
                  </h3>

                  <strong>
                    {analytics.failed_logins}
                  </strong>

                  <span>
                    Authentication failures
                  </span>

                </div>


                <div className="card">

                  <h3>
                    Successful Logins
                  </h3>

                  <strong>
                    {analytics.successful_logins}
                  </strong>

                  <span>
                    Authentication successes
                  </span>

                </div>


                <div className="card danger">

                  <h3>
                    Threat Events
                  </h3>

                  <strong>
                    {analytics.threat_events}
                  </strong>

                  <span>
                    Detected security threats
                  </span>

                </div>


              </div>


              {/* ------------------------------------------
                  ANALYTICS GRID
              ------------------------------------------ */}

              <div className="analytics-grid">


                {/* ----------------------------------------
                    SEVERITY DISTRIBUTION
                ---------------------------------------- */}

                <div className="panel">

                  <div style={{ padding: "22px" }}>

                    <h3>
                      ⚠️ Severity Distribution
                    </h3>


                    <div className="severity-list">


                      {/* CRITICAL */}

                      <div className="severity-row">

                        <div className="severity-label">

                          <span>
                            🔴 CRITICAL
                          </span>

                          <strong>
                            {
                              analytics
                                .severity_distribution
                                ?.CRITICAL || 0
                            }
                          </strong>

                        </div>


                        <div className="severity-bar">

                          <div
                            className="severity-fill severity-critical"
                            style={{
                              width: `${
                                analytics.total_events > 0
                                  ? (
                                      (
                                        analytics
                                          .severity_distribution
                                          ?.CRITICAL || 0
                                      ) /
                                      analytics.total_events
                                    ) * 100
                                  : 0
                              }%`
                            }}
                          />

                        </div>

                      </div>


                      {/* HIGH */}

                      <div className="severity-row">

                        <div className="severity-label">

                          <span>
                            🟠 HIGH
                          </span>

                          <strong>
                            {
                              analytics
                                .severity_distribution
                                ?.HIGH || 0
                            }
                          </strong>

                        </div>


                        <div className="severity-bar">

                          <div
                            className="severity-fill severity-high"
                            style={{
                              width: `${
                                analytics.total_events > 0
                                  ? (
                                      (
                                        analytics
                                          .severity_distribution
                                          ?.HIGH || 0
                                      ) /
                                      analytics.total_events
                                    ) * 100
                                  : 0
                              }%`
                            }}
                          />

                        </div>

                      </div>


                      {/* MEDIUM */}

                      <div className="severity-row">

                        <div className="severity-label">

                          <span>
                            🟡 MEDIUM
                          </span>

                          <strong>
                            {
                              analytics
                                .severity_distribution
                                ?.MEDIUM || 0
                            }
                          </strong>

                        </div>


                        <div className="severity-bar">

                          <div
                            className="severity-fill severity-medium"
                            style={{
                              width: `${
                                analytics.total_events > 0
                                  ? (
                                      (
                                        analytics
                                          .severity_distribution
                                          ?.MEDIUM || 0
                                      ) /
                                      analytics.total_events
                                    ) * 100
                                  : 0
                              }%`
                            }}
                          />

                        </div>

                      </div>


                      {/* LOW */}

                      <div className="severity-row">

                        <div className="severity-label">

                          <span>
                            🟢 LOW
                          </span>

                          <strong>
                            {
                              analytics
                                .severity_distribution
                                ?.LOW || 0
                            }
                          </strong>

                        </div>


                        <div className="severity-bar">

                          <div
                            className="severity-fill severity-low"
                            style={{
                              width: `${
                                analytics.total_events > 0
                                  ? (
                                      (
                                        analytics
                                          .severity_distribution
                                          ?.LOW || 0
                                      ) /
                                      analytics.total_events
                                    ) * 100
                                  : 0
                              }%`
                            }}
                          />

                        </div>

                      </div>


                    </div>

                  </div>

                </div>


                {/* ----------------------------------------
                    TOP SOURCE IPS
                ---------------------------------------- */}

                <div className="panel">

                  <div style={{ padding: "22px" }}>

                    <h3>
                      🌐 Top Source IPs
                    </h3>


                    <div
                      className="table-container"
                      style={{
                        marginTop: "15px"
                      }}
                    >

                      {topSourceIPs.length > 0 ? (

                        <table>

                          <thead>

                            <tr>

                              <th>
                                Source IP
                              </th>

                              <th>
                                Events
                              </th>

                            </tr>

                          </thead>


                          <tbody>

                            {topSourceIPs.map(
                              (ip, index) => (

                              <tr
                                key={`${String(ip.source_ip)}-${index}`}
                              >

                                <td>
                                  <div
                                    className="ip-display"
                                    style={{
                                      display: "flex",
                                      alignItems: "center",
                                      gap: "12px",
                                      marginRight: "12px",
                                    }}
                                  >
                                    <span
                                      className="ip-rank"
                                      style={{
                                        display: "inline-flex",
                                        alignItems: "center",
                                        justifyContent: "center",
                                        width: "28px",
                                        height: "28px",
                                        marginRight: "0",
                                        flexShrink: 0,
                                      }}
                                    >
                                      {index + 1}
                                    </span>

                                    <strong
                                      className="ip-address"
                                      title={String(ip.source_ip)}
                                      style={{
                                        display: "inline-block",
                                        whiteSpace: "normal",
                                        overflowWrap: "anywhere",
                                        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                                      }}
                                    >
                                      {formatSourceIP(ip.source_ip)}
                                    </strong>
                                  </div>
                                </td>


                                <td>

                                  <span className="ip-count">
                                    {ip.event_count}
                                  </span>

                                </td>

                              </tr>

                            )
                            )}

                          </tbody>

                        </table>

                      ) : (

                        <p
                          style={{
                            padding: "20px"
                          }}
                        >
                          No source IP activity detected.
                        </p>

                      )}

                    </div>

                  </div>

                </div>


              </div>


            </>

          )}

        </section>


        {/* ==================================================
            ALERT HISTORY MANAGEMENT
        ================================================== */}
        <section className="panel" id="alert-management">
          <div className="panel-header">
            <div>
              <h2>🗂️ Alert Management</h2>
              <p>Review historical alerts and acknowledge or resolve incidents</p>
            </div>
            <button onClick={fetchAlertHistory} disabled={historyLoading}>
              {historyLoading ? "Loading..." : "↻ Refresh History"}
            </button>
          </div>

          <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", padding: "0 20px 18px" }}>
            <input
              value={historySearch}
              onChange={(event) => setHistorySearch(event.target.value)}
              placeholder="Search alert, username, IP, or host..."
              style={{ minWidth: "230px", flex: "1", padding: "10px 12px", borderRadius: "8px", border: "1px solid #294768", background: "#081525", color: "#e2e8f0" }}
            />
            <select value={historyStatusFilter} onChange={(event) => setHistoryStatusFilter(event.target.value)}
              style={{ padding: "10px", borderRadius: "8px", background: "#081525", color: "#e2e8f0", border: "1px solid #294768" }}>
              <option value="ALL">All statuses</option>
              <option value="OPEN">OPEN</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
            <select value={historySeverityFilter} onChange={(event) => setHistorySeverityFilter(event.target.value)}
              style={{ padding: "10px", borderRadius: "8px", background: "#081525", color: "#e2e8f0", border: "1px solid #294768" }}>
              <option value="ALL">All severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {historyError && <p style={{ padding: "0 20px 15px", color: "#f87171" }}>{historyError}</p>}
          {historyLoading ? (
            <p style={{ padding: "20px" }}>Loading alert history...</p>
          ) : (
            (() => {
              const term = historySearch.trim().toLowerCase();
              const visibleHistory = alertHistory.filter((item) => {
                const status = String(item.status || "OPEN").toUpperCase();
                const severity = String(item.severity || "LOW").toUpperCase();
                const searchable = [item.alert, item.threat_type, item.username, item.source_ip, item.host, item.message].join(" ").toLowerCase();
                return (historyStatusFilter === "ALL" || status === historyStatusFilter) &&
                  (historySeverityFilter === "ALL" || severity === historySeverityFilter) &&
                  (!term || searchable.includes(term));
              });
              return (
                <div className="table-container">
                  {visibleHistory.length === 0 ? (
                    <p style={{ padding: "20px" }}>
                      {alertHistory.length === 0 ? "No historical alerts found yet." : "No alerts match these filters."}
                    </p>
                  ) : (
                    <table>
                      <thead>
                        <tr>
                          <th>Alert</th><th>Severity</th><th>Risk</th><th>User</th><th>Source IP</th><th>Time</th><th>Status</th><th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleHistory.map((item, index) => {
                          const id = item.history_id || item.alert_id || item.id;
                          const status = String(item.status || "OPEN").toUpperCase();
                          const severity = String(item.severity || "LOW").toUpperCase();
                          const busy = updatingAlertId === id;
                          return (
                            <tr key={id || index}>
                              <td>
                                <strong>{item.alert || item.threat_type || "Security alert"}</strong>
                                <div style={{ color: "#94a3b8", fontSize: "12px", marginTop: "4px" }}>{item.threat_type || item.message || ""}</div>
                              </td>
                              <td><span className={severity === "CRITICAL" ? "severity-critical" : severity === "HIGH" ? "severity-high" : severity === "MEDIUM" ? "severity-medium" : "severity-low"}>{severity}</span></td>
                              <td>{item.risk_score ?? "-"}</td>
                              <td>{item.username || "-"}</td>
                              <td>{item.source_ip || "-"}</td>
                              <td>{item.last_seen || item.event_timestamp || item.first_seen ? new Date(item.last_seen || item.event_timestamp || item.first_seen).toLocaleString() : "-"}</td>
                              <td><strong style={{ color: status === "RESOLVED" ? "#4ade80" : status === "ACKNOWLEDGED" ? "#facc15" : "#f87171" }}>{status}</strong></td>
                              <td>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                  {status === "OPEN" && <button disabled={busy} onClick={() => updateAlertStatus(item, "ACKNOWLEDGED")}>{busy ? "Updating..." : "Acknowledge"}</button>}
                                  {status !== "RESOLVED" && <button disabled={busy} onClick={() => updateAlertStatus(item, "RESOLVED")}>{busy ? "Updating..." : "Resolve"}</button>}
                                  <button disabled={incidentBusyId === id || incidents.some((incident) => incident.alert_history_id === id)} onClick={() => createIncident(item)}>
                                    {incidents.some((incident) => incident.alert_history_id === id) ? "Incident Created" : incidentBusyId === id ? "Creating..." : "Create Incident"}
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              );
            })()
          )}
        </section>

        {/* ==================================================
            INCIDENT MANAGEMENT
        ================================================== */}
        <section className="panel" id="incidents" style={{ scrollMarginTop: "24px" }}>
          <div className="panel-header">
            <div>
              <h2>🧾 Incident Management</h2>
              <p>Track security incidents, assign analysts, update workflow status and record investigation notes.</p>
            </div>
            <button onClick={fetchIncidents} disabled={incidentsLoading}>
              {incidentsLoading ? "Loading..." : "↻ Refresh Incidents"}
            </button>
          </div>

          <div className="stats" style={{ padding: "18px 20px" }}>
            <div className="card"><h3>Total Incidents</h3><strong>{incidents.length}</strong><span>Recorded incidents</span></div>
            <div className="card warning"><h3>Open</h3><strong>{incidents.filter((item) => item.status === "OPEN").length}</strong><span>Awaiting investigation</span></div>
            <div className="card danger"><h3>Investigating</h3><strong>{incidents.filter((item) => item.status === "INVESTIGATING").length}</strong><span>Under analyst review</span></div>
            <div className="card"><h3>Resolved</h3><strong>{incidents.filter((item) => item.status === "RESOLVED").length}</strong><span>Closed incidents</span></div>
          </div>

          {incidentsError && <p style={{ padding: "0 20px 14px", color: "#f87171" }}>{incidentsError}</p>}
          {incidentsLoading ? (
            <p style={{ padding: "20px" }}>Loading incidents...</p>
          ) : incidents.length === 0 ? (
            <p style={{ padding: "20px" }}>No incidents yet. Create one from an alert in Alert Management.</p>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr><th>Alert</th><th>Severity</th><th>Priority</th><th>Source IP</th><th>Assigned To</th><th>Status</th><th>Notes</th><th>Details</th></tr>
                </thead>
                <tbody>
                  {incidents.map((incident) => {
                    const id = incident.incident_id;
                    const busy = incidentBusyId === id;
                    const expanded = selectedIncidentId === id;
                    return (
                      <Fragment key={id}>
                        <tr>
                          <td><strong>{incident.alert || "Security incident"}</strong><div style={{ color: "#94a3b8", fontSize: "12px" }}>{incident.username || "Unknown user"} · {incident.host || "Unknown host"}</div></td>
                          <td>{incident.severity || "-"}</td>
                          <td>{incident.priority || "-"}</td>
                          <td>{incident.source_ip || "-"}</td>
                          <td>
                            <input aria-label="Assigned analyst" defaultValue={incident.assigned_to || ""} placeholder="Analyst name"
                              onBlur={(event) => { if (event.target.value !== (incident.assigned_to || "")) updateIncident(incident, { assigned_to: event.target.value }); }}
                              style={{ width: "130px", padding: "7px", background: "#081525", color: "#e2e8f0", border: "1px solid #294768", borderRadius: "6px" }} />
                          </td>
                          <td>
                            <select value={incident.status || "OPEN"} disabled={busy} onChange={(event) => updateIncident(incident, { status: event.target.value })}
                              style={{ padding: "7px", background: "#081525", color: "#e2e8f0", border: "1px solid #294768", borderRadius: "6px" }}>
                              <option value="OPEN">OPEN</option><option value="INVESTIGATING">INVESTIGATING</option><option value="RESOLVED">RESOLVED</option>
                            </select>
                          </td>
                          <td>{Array.isArray(incident.notes) ? incident.notes.length : 0}</td>
                          <td><button onClick={() => setSelectedIncidentId(expanded ? null : id)}>{expanded ? "Hide" : "View"}</button></td>
                        </tr>
                        {expanded && (
                          <tr>
                            <td colSpan="8">
                              <div style={{ padding: "14px", display: "grid", gap: "12px", background: "#081525", borderRadius: "10px" }}>
                                <div><strong>Incident ID:</strong> <span style={{ overflowWrap: "anywhere" }}>{id}</span></div>
                                <div><strong>Event ID:</strong> {incident.event_id || "-"} · <strong>Risk:</strong> {incident.risk_score ?? "-"}</div>
                                <div><strong>Threat:</strong> {incident.threat_type || "-"}</div>
                                <div><strong>Message:</strong> {incident.message || "-"}</div>
                                {incident.simulation_only && <div style={{ color: "#fbbf24" }}>Simulation/test incident — not a confirmed real-world attack.</div>}
                                <h4 style={{ margin: "4px 0" }}>Investigation Notes</h4>
                                {(incident.notes || []).length === 0 ? <p>No notes added yet.</p> : (incident.notes || []).map((note, index) => (
                                  <div key={`${note.created_at || index}`} style={{ padding: "10px", border: "1px solid #294768", borderRadius: "8px" }}>
                                    <p style={{ margin: "0 0 6px" }}>{note.note}</p>
                                    <small style={{ color: "#94a3b8" }}>{note.author || "Unknown"} · {note.created_at ? new Date(note.created_at).toLocaleString() : ""}</small>
                                  </div>
                                ))}
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                                  <input value={incidentNoteDrafts[id] || ""} onChange={(event) => setIncidentNoteDrafts((current) => ({ ...current, [id]: event.target.value }))}
                                    placeholder="Write an investigation note..." style={{ flex: "1", minWidth: "220px", padding: "10px", background: "#0f1b31", color: "#e2e8f0", border: "1px solid #294768", borderRadius: "7px" }} />
                                  <button disabled={busy} onClick={() => addIncidentNote(incident)}>{busy ? "Saving..." : "Add Note"}</button>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* ==================================================
            SECURITY ALERTS
        ================================================== */}

        <section className="panel alerts-panel" id="alerts">

          <div className="panel-header">

            <div>

              <h2>
                🚨 Security Alerts
              </h2>

              <p>
                Detected threats from the last 5 minutes
              </p>

            </div>


            <button
              onClick={fetchAlerts}
            >
              Refresh Alerts
            </button>

          </div>


          {alertsLoading && (

            <p
              style={{
                padding: "20px"
              }}
            >
              Loading security alerts...
            </p>

          )}


          {alertsError && (

            <p
              style={{
                padding: "20px",
                color: "#f87171"
              }}
            >
              {alertsError}
            </p>

          )}


          {!alertsLoading &&
            !alertsError && (

            <div className="table-container">


              {alerts.length === 0 ? (

                <p
                  style={{
                    padding: "20px"
                  }}
                >
                  No active security alerts.
                </p>

              ) : (

                <table>

                  <thead>

                    <tr>

                      <th>
                        Alert
                      </th>

                      <th>
                        Threat Type
                      </th>

                      <th>
                        Severity
                      </th>

                      <th>
                        Risk Score
                      </th>

                      <th>
                        Username
                      </th>

                      <th>
                        Source IP
                      </th>

                      <th>
                        Time
                      </th>

                      <th>
                        Investigation
                      </th>

                    </tr>

                  </thead>


                  <tbody>

                    {alerts.map(
                      (alert, index) => (

                      <tr
                        key={`${alert.source_ip}-${alert["@timestamp"]}-${index}`}
                      >

                        <td>

                          <span className="alert-badge">
                            🚨 {alert.alert}
                          </span>

                        </td>


                        <td className="threat">
                          {alert.threat_type || "-"}
                        </td>


                        <td>

                          <span className="severity-high">
                            {alert.severity}
                          </span>

                        </td>


                        <td>

                          <strong>
                            {alert.risk_score}
                          </strong>

                        </td>


                        <td>
                          {alert.username || "-"}
                        </td>


                        <td>
                          {alert.source_ip || "-"}
                        </td>


                        <td>

                          {alert["@timestamp"]

                            ? new Date(
                                alert["@timestamp"]
                              ).toLocaleTimeString()

                            : "-"

                          }

                        </td>


                        <td>

                          <button
                            onClick={() =>
                              investigateIP(
                                alert.source_ip
                              )
                            }
                          >
                            🔎 Investigate
                          </button>

                        </td>


                      </tr>

                    ))}

                  </tbody>

                </table>

              )}

            </div>

          )}

        </section>


        {/* ==================================================
            UEBA ANALYSIS
        ================================================== */}
        <section className="panel" id="ueba">
          <div className="panel-header">
            <div>
              <h2>🧠 UEBA Analysis</h2>
              <p>User and Entity Behavior Analytics — anomalies identified by the backend</p>
            </div>
            <button onClick={fetchAlerts}>Refresh UEBA</button>
          </div>

          {alertsLoading ? (
            <p style={{ padding: "20px" }}>Loading UEBA analysis...</p>
          ) : alertsError ? (
            <p style={{ padding: "20px", color: "#f87171" }}>{alertsError}</p>
          ) : (
            <>
              <div className="stats">
                <div className="card">
                  <h3>UEBA Anomalies</h3>
                  <strong>{uebaAlerts.length}</strong>
                  <span>Backend-detected behavior anomalies</span>
                </div>
                <div className="card">
                  <h3>Entities Affected</h3>
                  <strong>{uebaEntities}</strong>
                  <span>Distinct users or source IPs</span>
                </div>
                <div className="card danger">
                  <h3>High / Critical</h3>
                  <strong>{uebaSeverityCounts.high + uebaSeverityCounts.critical}</strong>
                  <span>Higher-priority UEBA anomalies</span>
                </div>
                <div className="card warning">
                  <h3>Medium / Low</h3>
                  <strong>{uebaSeverityCounts.medium + uebaSeverityCounts.low}</strong>
                  <span>Review recommended</span>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: "12px", padding: "0 20px 20px" }}>
                {[
                  ["CRITICAL", uebaSeverityCounts.critical, "#ef4444"],
                  ["HIGH", uebaSeverityCounts.high, "#f97316"],
                  ["MEDIUM", uebaSeverityCounts.medium, "#eab308"],
                  ["LOW", uebaSeverityCounts.low, "#22c55e"],
                ].map(([label, count, color]) => (
                  <div key={label} style={{ padding: "14px", borderRadius: "10px", background: "#0b1728", border: `1px solid ${color}55` }}>
                    <div style={{ color, fontSize: "12px", fontWeight: 800 }}>{label}</div>
                    <strong style={{ display: "block", color: "#f8fafc", fontSize: "25px", marginTop: "5px" }}>{count}</strong>
                  </div>
                ))}
              </div>

              <div className="table-container">
                {uebaAlerts.length === 0 ? (
                  <p style={{ padding: "20px" }}>
                    No UEBA anomalies are currently being returned by the backend. This does not mean that all activity is risk-free; it means no UEBA alert is active in the current alert response.
                  </p>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Entity</th>
                        <th>Entity Type</th>
                        <th>Anomaly</th>
                        <th>Severity</th>
                        <th>Risk</th>
                        <th>Activity</th>
                        <th>Failed Logins</th>
                        <th>Baseline</th>
                        <th>Detection Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {uebaAlerts.map((alert, index) => {
                        const severity = String(alert.severity || "UNKNOWN").toUpperCase();
                        const severityClass = severity === "CRITICAL" ? "severity-critical" : severity === "HIGH" ? "severity-high" : severity === "MEDIUM" ? "severity-medium" : "severity-low";
                        return (
                          <tr key={`${alert.username || alert.source_ip || "entity"}-${alert.threat_type || "anomaly"}-${index}`}>
                            <td>{alert.username || alert.source_ip || "Unknown"}</td>
                            <td>{alert.entity_type || "UNKNOWN"}</td>
                            <td>{alert.threat_type || alert.alert || "Behavior anomaly"}</td>
                            <td><span className={severityClass}>{severity}</span></td>
                            <td><strong>{alert.risk_score ?? "-"}</strong></td>
                            <td>{alert.activity_count ?? "-"}</td>
                            <td>{alert.failed_login_count ?? "-"}</td>
                            <td>{alert.baseline_activity ?? "-"}</td>
                            <td>{alert.detection_reason || alert.message || "Unusual behavior"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
              <p style={{ padding: "12px 20px", color: "#94a3b8", fontSize: "12px" }}>
                Data source: existing backend UEBA anomaly detection included in the /alerts response. This page displays detected anomalies; it does not create synthetic anomaly records.
              </p>
            </>
          )}
        </section>


        {/* ==================================================
            IP MONITORING
        ================================================== */}

        <section className="panel" id="threat-intelligence">

          <div className="panel-header">

            <div>

              <h2>
                🌐 IP Monitoring
              </h2>

              <p>
                Source IP activity and threat risk from the last 5 minutes
              </p>

            </div>


            <button
              onClick={fetchIPMonitoring}
            >
              Refresh IPs
            </button>

          </div>


          {ipLoading && (

            <p
              style={{
                padding: "20px"
              }}
            >
              Loading IP monitoring data...
            </p>

          )}


          {ipError && (

            <p
              style={{
                padding: "20px",
                color: "#f87171"
              }}
            >
              {ipError}
            </p>

          )}


          {!ipLoading &&
            !ipError && (

            <div className="table-container">


              {ipMonitoring.length === 0 ? (

                <p
                  style={{
                    padding: "20px"
                  }}
                >
                  No IP activity detected in the last 5 minutes.
                </p>

              ) : (

                <table>

                  <thead>

                    <tr>

                      <th>
                        Source IP
                      </th>

                      <th>
                        Failed Logins
                      </th>

                      <th>
                        Successful Logins
                      </th>

                      <th>
                        Total Events
                      </th>

                      <th>
                        Risk Score
                      </th>

                      <th>
                        Severity
                      </th>

                      <th>
                        Status
                      </th>

                      <th>
                        Investigation
                      </th>

                    </tr>

                  </thead>


                  <tbody>

                    {ipMonitoring.map(
                      (ip) => (

                      <tr
                        key={ip.source_ip}
                      >

                        <td>

                          <strong>
                            {ip.source_ip}
                          </strong>

                        </td>


                        <td>
                          {ip.failed_logins}
                        </td>


                        <td>
                          {ip.successful_logins}
                        </td>


                        <td>
                          {ip.total_events}
                        </td>


                        <td>

                          <strong>
                            {ip.risk_score}
                          </strong>

                        </td>


                        <td>

                          <span className="severity-high">
                            {ip.severity}
                          </span>

                        </td>


                        <td>

                          <span className="alert-badge">
                            {ip.status}
                          </span>

                        </td>


                        <td>

                          <button
                            onClick={() =>
                              investigateIP(
                                ip.source_ip
                              )
                            }
                          >
                            🔎 Investigate
                          </button>

                        </td>

                      </tr>

                    ))}

                  </tbody>

                </table>

              )}

            </div>

          )}

        </section>


        {/* ==================================================
            THREAT INVESTIGATION
        ================================================== */}

        {investigating && (

          <section className="panel">

            <p
              style={{
                padding: "20px"
              }}
            >
              🔎 Investigating source IP...
            </p>

          </section>

        )}


        {investigation && (

          <section className="panel" id="investigation">

            <div className="panel-header">

              <div>

                <h2>
                  🔎 Threat Investigation
                </h2>

                <p>

                  Source IP:{" "}
                  {investigation.source_ip}

                  {" • "}

                  Related Events:{" "}
                  {investigation.total_events}

                </p>

              </div>


              <button
                onClick={() =>
                  setInvestigation(null)
                }
              >
                Close
              </button>

            </div>


            <div className="table-container">

              <table>

                <thead>

                  <tr>

                    <th>
                      Event Type
                    </th>

                    <th>
                      Username
                    </th>

                    <th>
                      Source IP
                    </th>

                    <th>
                      Threat
                    </th>

                    <th>
                      Message
                    </th>

                    <th>
                      Time
                    </th>

                  </tr>

                </thead>


                <tbody>

                  {investigation.events.map(
                    (event) => (

                    <tr
                      key={event.id}
                    >

                      <td>

                        <span className="badge">
                          {event.event_type}
                        </span>

                      </td>


                      <td>
                        {event.username || "-"}
                      </td>


                      <td>
                        {event.source_ip || "-"}
                      </td>


                      <td className="threat">
                        {event.threat_type || "None"}
                      </td>


                      <td>
                        {event.message || "-"}
                      </td>


                      <td>

                        {event["@timestamp"]

                          ? new Date(
                              event["@timestamp"]
                            ).toLocaleTimeString()

                          : "-"

                        }

                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          </section>

        )}


        {/* ==================================================
            RECENT SECURITY EVENTS
        ================================================== */}

        <section className="panel" id="events">

          <div className="panel-header">
            <div>
              <h2>Recent Security Events</h2>
              <p>
                {searchTerm
                  ? `Showing ${filteredEvents.length} matching event(s)`
                  : "Latest events received from monitored systems"}
              </p>
            </div>
            <button onClick={fetchEvents}>Refresh</button>
          </div>

          {loading && (
            <p style={{ padding: "20px" }}>Loading security events...</p>
          )}

          {error && (
            <p style={{ padding: "20px", color: "#f87171" }}>{error}</p>
          )}

          {!loading && !error && (
            <div className="table-container" style={{ overflowX: "auto", maxWidth: "100%" }}>
              {filteredEvents.length === 0 ? (
                <p style={{ padding: "20px" }}>No security events found.</p>
              ) : (
                <table style={{ width: "100%", minWidth: "980px", tableLayout: "fixed" }}>
                  <thead>
                    <tr>
                      <th style={{ width: "145px" }}>Event Type</th>
                      <th style={{ width: "90px" }}>Event ID</th>
                      <th style={{ width: "150px" }}>Host</th>
                      <th style={{ width: "120px" }}>Username</th>
                      <th style={{ width: "105px" }}>Severity</th>
                      <th style={{ width: "80px" }}>Risk</th>
                      <th style={{ width: "105px" }}>Time</th>
                      <th style={{ width: "120px" }}>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.map((event, index) => {
                      const severity = getEventSeverity(event);
                      const severityClass =
                        severity === "CRITICAL"
                          ? "severity-critical"
                          : severity === "HIGH"
                            ? "severity-high"
                            : severity === "MEDIUM"
                              ? "severity-medium"
                              : severity === "LOW"
                                ? "severity-low"
                                : "badge";

                      return (
                        <tr key={event.id || `${getEventId(event)}-${event["@timestamp"]}-${index}`}>
                          <td>
                            <span className="badge" style={{ display: "inline-block", maxWidth: "135px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={getEventTypeLabel(event)}>
                              {getEventTypeLabel(event)}
                            </span>
                          </td>
                          <td><strong>{getEventId(event)}</strong></td>
                          <td title={getEventHost(event)} style={{ maxWidth: "150px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {getEventHost(event)}
                          </td>
                          <td title={getEventUsername(event)} style={{ maxWidth: "120px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {getEventUsername(event)}
                          </td>
                          <td><span className={severityClass}>{severity}</span></td>
                          <td><strong>{event.risk_score !== undefined && event.risk_score !== null ? event.risk_score : "-"}</strong></td>
                          <td>{getEventTime(event)}</td>
                          <td>
                            <button onClick={() => setSelectedEvent(event)} style={{ padding: "7px 11px", borderRadius: "8px", border: "1px solid rgba(56, 189, 248, 0.35)", background: "rgba(14, 165, 233, 0.10)", color: "#7dd3fc", cursor: "pointer", fontWeight: 700, fontSize: "12px" }}>
                              🔎 View
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </section>

        {selectedEvent && (
          <div onClick={() => setSelectedEvent(null)} style={{ position: "fixed", inset: 0, zIndex: 9999, background: "rgba(2, 6, 23, 0.78)", backdropFilter: "blur(6px)", display: "flex", alignItems: "center", justifyContent: "center", padding: "24px" }}>
            <div onClick={(event) => event.stopPropagation()} style={{ width: "min(900px, 100%)", maxHeight: "85vh", overflowY: "auto", background: "linear-gradient(145deg, #0f1b31 0%, #08111f 100%)", border: "1px solid #294768", borderRadius: "16px", boxShadow: "0 25px 80px rgba(0, 0, 0, 0.55)", padding: "24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "20px", marginBottom: "20px" }}>
                <div>
                  <h2 style={{ margin: 0, color: "#f8fafc" }}>🔎 Security Event Details</h2>
                  <p style={{ margin: "7px 0 0", color: "#94a3b8" }}>{getEventHost(selectedEvent)} • Event ID {getEventId(selectedEvent)}</p>
                </div>
                <button onClick={() => setSelectedEvent(null)}>Close</button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px", marginBottom: "20px" }}>
                {[
                  ["Event Type", getEventTypeLabel(selectedEvent)],
                  ["Event ID", getEventId(selectedEvent)],
                  ["Host", getEventHost(selectedEvent)],
                  ["Username", getEventUsername(selectedEvent)],
                  ["Severity", getEventSeverity(selectedEvent)],
                  ["Risk Score", selectedEvent.risk_score !== undefined && selectedEvent.risk_score !== null ? selectedEvent.risk_score : "-"],
                  ["Threat", selectedEvent.threat_type || "None"],
                  ["Time", getEventTime(selectedEvent)]
                ].map(([label, value]) => (
                  <div key={label} style={{ padding: "14px", borderRadius: "10px", background: "rgba(15, 23, 42, 0.75)", border: "1px solid #243b5a" }}>
                    <span style={{ display: "block", color: "#64748b", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "6px" }}>{label}</span>
                    <strong style={{ color: "#e2e8f0", wordBreak: "break-word" }}>{value}</strong>
                  </div>
                ))}
              </div>

              <div>
                <h3 style={{ marginBottom: "10px", color: "#e2e8f0" }}>Full Event Message</h3>
                <pre style={{ margin: 0, padding: "18px", borderRadius: "12px", background: "#050b15", border: "1px solid #1e3550", color: "#cbd5e1", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.55, fontSize: "13px", maxHeight: "360px", overflowY: "auto" }}>
                  {selectedEvent.message || "No event message available."}
                </pre>
              </div>
            </div>
          </div>
        )}


        <section className="panel" id="reports" style={{ scrollMarginTop: "24px" }}>
          <div className="panel-header">
            <div>
              <h2>📄 Security Reports</h2>
              <p>Review current SIEM activity and export records for further analysis.</p>
            </div>
            <button onClick={() => window.print()}>Print Report</button>
          </div>
          <div className="stats" style={{ padding: "20px" }}>
            <div className="card"><h3>Events Loaded</h3><strong>{totalEvents}</strong><span>Events currently available in the dashboard</span></div>
            <div className="card danger"><h3>Detected Threats</h3><strong>{threatsDetected}</strong><span>Threat-tagged events currently loaded</span></div>
            <div className="card warning"><h3>Failed Logins</h3><strong>{failedLogins}</strong><span>Failed authentication events currently loaded</span></div>
            <div className="card"><h3>Historical Alerts</h3><strong>{alertHistory.length}</strong><span>Records returned by alert history</span></div>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", padding: "0 20px 20px" }}>
            <button onClick={() => downloadReport("events")}>⬇ Export Events (CSV)</button>
            <button onClick={() => downloadReport("alerts")}>⬇ Export Alert History (CSV)</button>
            <button onClick={() => { fetchEvents(); fetchAlertHistory(); fetchAnalytics(); }}>↻ Refresh Report Data</button>
          </div>
          <p style={{ padding: "0 20px 18px", color: "#94a3b8", fontSize: "12px" }}>
            Reports contain the data currently returned by the backend and loaded in this application. Exported CSV files can be opened in Excel.
          </p>
        </section>

      </main>

    </div>

  );

}

export default App;