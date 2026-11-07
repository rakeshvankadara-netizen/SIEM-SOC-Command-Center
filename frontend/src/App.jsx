import { Fragment, useEffect, useRef, useState } from "react";
import "./App.css";
import Network3D from "./Network3D";

const API_URL = "http://127.0.0.1:8001";

function App() {
  const [authReady, setAuthReady] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [authToken, setAuthToken] = useState(() => sessionStorage.getItem("siem_token") || "");
  const [currentUser, setCurrentUser] = useState(null);
  const [loginUsername, setLoginUsername] = useState("admin");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [alertHistory, setAlertHistory] = useState([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyPage, setHistoryPage] = useState(0);
  const [historyPageSize] = useState(100);
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
  const historySearchTimerRef = useRef(null);
  const historyPageRef = useRef(historyPage);
  const historyStatusFilterRef = useRef(historyStatusFilter);
  const historySeverityFilterRef = useRef(historySeverityFilter);
  const historySearchRef = useRef(historySearch);
  const historyRequestIdRef = useRef(0);
  historyPageRef.current = historyPage;
  historyStatusFilterRef.current = historyStatusFilter;
  historySeverityFilterRef.current = historySeverityFilter;
  historySearchRef.current = historySearch;
  const [updatingAlertId, setUpdatingAlertId] = useState(null);
  const [ipMonitoring, setIpMonitoring] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [investigationIP, setInvestigationIP] = useState("198.51.100.25");
  const [investigationError, setInvestigationError] = useState("");
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
  // AUTHENTICATION
  // --------------------------------------------------

  const logout = () => {
    sessionStorage.removeItem("siem_token");
    setAuthToken("");
    setCurrentUser(null);
    setIsAuthenticated(false);
    setEvents([]);
    setAlerts([]);
    setAlertHistory([]);
    setHistoryTotal(0);
    setHistoryPage(0);
    setIncidents([]);
  };

  const apiFetch = async (url, options = {}) => {
    const token = authToken || sessionStorage.getItem("siem_token");
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (token) headers.set("Authorization", `Bearer ${token}`);

    const response = await fetch(url, { ...options, headers });
    if (response.status === 401) {
      logout();
      throw new Error("Your session expired. Please sign in again.");
    }
    return response;
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    setLoginLoading(true);
    setLoginError("");
    try {
      const body = new URLSearchParams();
      body.set("grant_type", "password");
      body.set("username", loginUsername.trim());
      body.set("password", loginPassword);
      const response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
        body: body.toString(),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Login failed. Check your credentials.");
      if (!data.access_token) throw new Error("The backend did not return an access token.");

      sessionStorage.setItem("siem_token", data.access_token);
      setAuthToken(data.access_token);
      setCurrentUser({ username: loginUsername.trim(), role: "admin" });
      setIsAuthenticated(true);
      setLoginPassword("");
    } catch (err) {
      setLoginError(err.message || "Unable to sign in.");
    } finally {
      setLoginLoading(false);
    }
  };

  useEffect(() => {
    const savedToken = sessionStorage.getItem("siem_token");
    if (!savedToken) {
      setAuthReady(true);
      return;
    }
    fetch(`${API_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${savedToken}`, Accept: "application/json" },
    })
      .then(async (response) => {
        if (!response.ok) throw new Error("Session expired");
        const user = await response.json();
        setCurrentUser(user);
        setAuthToken(savedToken);
        setIsAuthenticated(true);
      })
      .catch(() => {
        sessionStorage.removeItem("siem_token");
        setAuthToken("");
        setIsAuthenticated(false);
        setCurrentUser(null);
      })
      .finally(() => setAuthReady(true));
  }, []);

  // --------------------------------------------------
  // FETCH SECURITY EVENTS
  // --------------------------------------------------

  const fetchEvents = async (eventId = null) => {
    try {
      setLoading(true);
      setError("");
      const params = new URLSearchParams({ limit: "500" });
      if (eventId && /^\d+$/.test(eventId.trim())) {
        params.set("event_id", eventId.trim());
      }
      const response = await apiFetch(`${API_URL}/events?${params.toString()}`);
      if (!response.ok) throw new Error("Failed to fetch events");
      const data = await response.json();
      setEvents(data.events || []);
    } catch (err) {
      setError("Unable to connect to SIEM backend");
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
      const response = await apiFetch(`${API_URL}/alerts`);
      if (!response.ok) throw new Error("Failed to fetch alerts");
      const data = await response.json();
      setAlerts(data.alerts || []);
    } catch (err) {
      setAlertsError("Unable to load security alerts");
    } finally {
      setAlertsLoading(false);
    }
  };

  // --------------------------------------------------
  // ALERT HISTORY AND STATUS MANAGEMENT
  // --------------------------------------------------

  const fetchAlertHistory = async (
    page = historyPageRef.current,
    statusFilter = historyStatusFilterRef.current,
    searchText = historySearchRef.current,
    severityFilter = historySeverityFilterRef.current
  ) => {
    // Sanitize the page argument so passing click events doesn't create offset=NaN
    const safePage = (typeof page === "number" && !Number.isNaN(page)) ? page : (historyPageRef.current || 0);

    const requestId = ++historyRequestIdRef.current;
    try {
      setHistoryLoading(true);
      setHistoryError("");

      const params = new URLSearchParams({
        limit: String(historyPageSize),
        offset: String(safePage * historyPageSize),
      });

      if (statusFilter !== "ALL") params.set("status", statusFilter);
      if (severityFilter !== "ALL") params.set("severity", severityFilter);
      if (searchText.trim()) params.set("q", searchText.trim());

      const response = await apiFetch(`${API_URL}/alert-history?${params.toString()}`);
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Failed to fetch alert history");
      }

      let data = await response.json();
      const total = Number(data.total || 0);
      const lastPage = Math.max(0, Math.ceil(total / historyPageSize) - 1);

      let pageToFetch = safePage;
      if (pageToFetch > lastPage) {
        pageToFetch = lastPage;
        params.set("offset", String(pageToFetch * historyPageSize));
        const correctedResponse = await apiFetch(`${API_URL}/alert-history?${params.toString()}`);
        if (!correctedResponse.ok) {
          const message = await correctedResponse.text();
          throw new Error(message || "Failed to fetch alert history");
        }
        data = await correctedResponse.json();
      }

      if (requestId !== historyRequestIdRef.current) return;
      setAlertHistory(data.alerts || []);
      setHistoryTotal(total);
      setHistoryPage(pageToFetch);
    } catch (err) {
      if (requestId === historyRequestIdRef.current) {
        setHistoryError(`Unable to load alert history. ${err.message || "Check that the backend is running."}`);
      }
    } finally {
      if (requestId === historyRequestIdRef.current) {
        setHistoryLoading(false);
      }
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
      const response = await apiFetch(
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
      const response = await apiFetch(`${API_URL}/incidents`);
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
      const response = await apiFetch(`${API_URL}/incidents`, {
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
      const response = await apiFetch(`${API_URL}/incidents/${encodeURIComponent(id)}`, {
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
      const response = await apiFetch(`${API_URL}/incidents/${encodeURIComponent(id)}/notes`, {
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
  // FETCH IP MONITORING, ANALYTICS, HOSTS
  // --------------------------------------------------

  const fetchIPMonitoring = async () => {
    try {
      setIpLoading(true);
      setIpError("");
      const response = await apiFetch(`${API_URL}/ip-monitoring`);
      if (!response.ok) throw new Error("Failed to fetch IP monitoring");
      const data = await response.json();
      setIpMonitoring(data.ips || []);
    } catch (err) {
      setIpError("Unable to load IP monitoring data");
    } finally {
      setIpLoading(false);
    }
  };

  const fetchAnalytics = async () => {
    try {
      setAnalyticsLoading(true);
      setAnalyticsError("");
      const response = await apiFetch(`${API_URL}/analytics`);
      if (!response.ok) throw new Error("Failed to fetch analytics");
      const data = await response.json();
      setAnalytics(data);
    } catch (err) {
      setAnalyticsError("Unable to load security analytics");
    } finally {
      setAnalyticsLoading(false);
    }
  };

  const fetchHosts = async () => {
    try {
      const response = await apiFetch(`${API_URL}/hosts`);
      if (!response.ok) throw new Error("Failed to fetch monitored hosts");
      const data = await response.json();
      setHosts(data.hosts || []);
    } catch (err) {
      console.error("Failed to fetch monitored hosts:", err);
    }
  };

  const investigateIP = async (sourceIP) => {
    const ip = String(sourceIP || "").trim();
    if (!ip) {
      setInvestigationError("Please enter a source IP address.");
      return;
    }
    try {
      setInvestigating(true);
      setInvestigation(null);
      setInvestigationError("");
      setInvestigationIP(ip);
      const response = await apiFetch(`${API_URL}/investigate/${encodeURIComponent(ip)}`);
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(detail || `Investigation failed (${response.status})`);
      }
      const data = await response.json();
      setInvestigation(data);
    } catch (err) {
      console.error("Investigation failed:", err);
      setInvestigationError(err.message || "Unable to investigate this IP.");
    } finally {
      setInvestigating(false);
    }
  };

  // --------------------------------------------------
  // CLOCK & ROUTING LISTENERS
  // --------------------------------------------------

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const updateActiveSection = () => {
      const hash = window.location.hash.slice(1);
      setActiveSection(hash || "dashboard");
    };
    window.addEventListener("hashchange", updateActiveSection);
    return () => window.removeEventListener("hashchange", updateActiveSection);
  }, []);

  // --------------------------------------------------
  // INITIAL LOAD & WEBSOCKET
  // --------------------------------------------------

  useEffect(() => {
    if (!isAuthenticated) return;

    fetchEvents();
    fetchAlerts();
    fetchAlertHistory();
    fetchIncidents();
    fetchIPMonitoring();
    fetchAnalytics();
    fetchHosts();

    let lastAlertRefresh = Date.now();
    const socketToken = authToken || sessionStorage.getItem("siem_token");
    if (!socketToken) {
      logout();
      return;
    }

    const socketUrl = new URL(`${API_URL.replace(/^http/, "ws")}/ws/events`);
    socketUrl.searchParams.set("token", socketToken);
    const socket = new WebSocket(socketUrl.toString());

    socket.onopen = () => console.log("WebSocket connected");
    socket.onmessage = (message) => {
      const data = JSON.parse(message.data);
      if (data.events) {
        const activeSearch = searchTermRef.current.trim();
        if (!/^\d+$/.test(activeSearch)) setEvents(data.events);
        setLoading(false);
        setError("");
        fetchHosts();

        if (Date.now() - lastAlertRefresh >= 10000) {
          lastAlertRefresh = Date.now();
          fetchAlerts();
          fetchAlertHistory();
          fetchIncidents();
        }
      }
    };
    socket.onerror = () => {
      console.error("WebSocket connection failed");
      setError("WebSocket connection failed");
    };
    socket.onclose = () => console.log("WebSocket disconnected");

    return () => socket.close();
  }, [isAuthenticated, authToken]);

  // --------------------------------------------------
  // DERIVED METRICS
  // --------------------------------------------------

  const totalEvents = events.length;
  const threatsDetected = events.filter((e) => e.threat_type).length;

  const failedLogins = events.filter((event) => {
    const eventType = Array.isArray(event.event_type)
      ? event.event_type.join(" ").toLowerCase()
      : String(event.event_type || "").toLowerCase();
    const eventId = String(event.winlog?.event_id ?? event.event?.code ?? event.event_id ?? "");
    return eventType.includes("login_failed") || eventType.includes("login-failed") || eventId === "4625";
  }).length;

  const highSeverityAlerts = events.filter((e) => e.severity === "HIGH" || e.severity === "CRITICAL").length;

  const criticalThreats = alerts.filter((a) => a.severity === "CRITICAL").length;
  const highThreats = alerts.filter((a) => a.severity === "HIGH").length;
  const mediumThreats = alerts.filter((a) => a.severity === "MEDIUM").length;
  const lowThreats = alerts.filter((a) => a.severity === "LOW").length;

  const uebaAlerts = alerts.filter(
    (alert) => String(alert.alert || "").toLowerCase().includes("ueba") || Boolean(alert.entity_type)
  );
  const uebaSeverityCounts = {
    critical: uebaAlerts.filter((a) => a.severity === "CRITICAL").length,
    high: uebaAlerts.filter((a) => a.severity === "HIGH").length,
    medium: uebaAlerts.filter((a) => a.severity === "MEDIUM").length,
    low: uebaAlerts.filter((a) => a.severity === "LOW").length,
  };
  const uebaEntities = new Set(uebaAlerts.map((a) => a.username || a.source_ip || "Unknown")).size;

  const threatScore = Math.min(100, criticalThreats * 25 + highThreats * 10 + mediumThreats * 5 + lowThreats * 2);
  const threatLevel =
    threatScore >= 75 ? "CRITICAL" : threatScore >= 50 ? "HIGH" : threatScore >= 25 ? "MEDIUM" : "LOW";

  const normalizedSearch = searchTerm.trim().toLowerCase();
  const filteredEvents = normalizedSearch
    ? events.filter((event) => {
        const eventId = String(event.winlog?.event_id ?? event.event?.code ?? event.event_id ?? "").toLowerCase();
        return eventId.includes(normalizedSearch) || JSON.stringify(event).toLowerCase().includes(normalizedSearch);
      })
    : events;

  useEffect(() => {
    if (!isAuthenticated) return;
    const term = searchTerm.trim();
    if (term === "") {
      fetchEvents();
      return;
    }
    if (!/^\d+$/.test(term)) return;
    const timer = setTimeout(() => fetchEvents(term), 300);
    return () => clearTimeout(timer);
  }, [searchTerm, isAuthenticated]);

  const liveTime = currentTime.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  const getEventUsername = (e) =>
    e.username || e.user?.name || e.winlog?.event_data?.TargetUserName || e.winlog?.event_data?.SubjectUserName || "-";
  const getEventHost = (e) => e.host?.hostname || e.host?.name || e.hostname || "-";
  const getEventId = (e) => e.winlog?.event_id || e.event?.code || e.event_id || "-";
  const getEventSeverity = (e) => e.severity || (e.alert ? "ALERT" : "Normal");
  const getEventTime = (e) => (e["@timestamp"] ? new Date(e["@timestamp"]).toLocaleTimeString() : "-");
  const getEventTypeLabel = (e) => (Array.isArray(e?.event_type) ? e.event_type.join(" · ") : e?.event_type || "security_event");

  const formatSourceIP = (value) => {
    if (Array.isArray(value)) value = value[0];
    if (value === null || value === undefined || String(value).trim() === "" || String(value).trim() === "-") {
      return "Unknown";
    }
    const ip = String(value).trim();
    if (ip === "::1" || ip === "127.0.0.1") return `Localhost (${ip})`;
    return ip;
  };

  const renderIPReputation = (alert) => {
    const reputation = String(alert?.ip_reputation || alert?.ip_reputation_details?.reputation || "").toUpperCase();
    if (!reputation) return <span style={{ color: "#64748b" }}>Not checked</span>;

    const reputationColors = {
      MALICIOUS: { color: "#f87171", background: "rgba(127,29,29,.25)", border: "#ef4444" },
      SUSPICIOUS: { color: "#fb923c", background: "rgba(124,45,18,.25)", border: "#f97316" },
      SIMULATED: { color: "#facc15", background: "rgba(113,63,18,.25)", border: "#eab308" },
      UNKNOWN: { color: "#94a3b8", background: "rgba(51,65,85,.3)", border: "#64748b" },
      INVALID: { color: "#cbd5e1", background: "rgba(71,85,105,.3)", border: "#94a3b8" },
    };
    const style = reputationColors[reputation] || reputationColors.UNKNOWN;
    const risk = alert.ip_reputation_risk ?? alert.ip_reputation_details?.risk_score;
    const confidence = alert.ip_reputation_confidence ?? alert.ip_reputation_details?.confidence;
    const threatType = alert.ip_threat_type || alert.ip_reputation_details?.threat_type;
    const source = alert.ip_reputation_source || alert.ip_reputation_details?.source;

    return (
      <div style={{ minWidth: "145px", display: "flex", flexDirection: "column", alignItems: "flex-start", gap: "5px" }}>
        <span style={{ display: "inline-block", padding: "4px 8px", borderRadius: "6px", color: style.color, background: style.background, border: `1px solid ${style.border}`, fontSize: "11px", fontWeight: 800 }}>
          {reputation}
        </span>
        {threatType && <small style={{ color: "#cbd5e1", maxWidth: "190px", whiteSpace: "normal" }}>{threatType}</small>}
        {(risk !== undefined || confidence !== undefined) && (
          <small style={{ color: "#94a3b8" }}>Risk: {risk ?? "-"} / Confidence: {confidence ?? "-"}%</small>
        )}
        {source && <small style={{ color: "#64748b", maxWidth: "190px", whiteSpace: "normal" }}>{source}</small>}
      </div>
    );
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

  if (!authReady) {
    return (
      <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "#07111f", color: "#e2e8f0", fontFamily: "Arial, sans-serif" }}>
        <p>Checking secure SIEM session...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: "24px", background: "radial-gradient(circle at top, #142b49 0%, #07111f 55%)", color: "#e2e8f0", fontFamily: "Arial, sans-serif" }}>
        <form onSubmit={handleLogin} style={{ width: "min(420px, 100%)", padding: "36px", borderRadius: "18px", background: "rgba(10, 22, 40, 0.96)", border: "1px solid #294768", boxShadow: "0 24px 80px rgba(0,0,0,.4)" }}>
          <div style={{ textAlign: "center", fontSize: "42px" }}>🛡️</div>
          <h1 style={{ textAlign: "center", margin: "12px 0 6px", color: "#f8fafc" }}>SIEM SOC</h1>
          <p style={{ textAlign: "center", color: "#94a3b8", margin: "0 0 28px" }}>Sign in to your Security Operations Center</p>
          <label style={{ display: "block", marginBottom: "8px", color: "#cbd5e1" }}>Username</label>
          <input value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)} autoComplete="username" required style={{ width: "100%", boxSizing: "border-box", padding: "12px", marginBottom: "18px", borderRadius: "8px", border: "1px solid #294768", background: "#081525", color: "#e2e8f0" }} />
          <label style={{ display: "block", marginBottom: "8px", color: "#cbd5e1" }}>Password</label>
          <input type="password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} autoComplete="current-password" required style={{ width: "100%", boxSizing: "border-box", padding: "12px", marginBottom: "18px", borderRadius: "8px", border: "1px solid #294768", background: "#081525", color: "#e2e8f0" }} />
          {loginError && <p role="alert" style={{ color: "#f87171", margin: "0 0 16px" }}>{loginError}</p>}
          <button type="submit" disabled={loginLoading} style={{ width: "100%", padding: "13px", border: 0, borderRadius: "8px", background: "#2563eb", color: "white", fontWeight: 700, cursor: "pointer" }}>
            {loginLoading ? "Signing in..." : "Sign In"}
          </button>
          <p style={{ textAlign: "center", color: "#64748b", fontSize: "12px", marginTop: "20px" }}>Authorized personnel only</p>
        </form>
      </div>
    );
  }

  // Helper boolean flags for route matching
  const isDashboard = activeSection === "dashboard" || activeSection === "";
  const isHosts = activeSection === "hosts";
  const isEvents = activeSection === "events";
  const isAlerts = activeSection === "alerts";
  const isAlertManagement = activeSection === "alert-management";
  const isIncidents = activeSection === "incidents";
  const isThreatIntel = activeSection === "threat-intelligence";
  const isUeba = activeSection === "ueba";
  const isNetwork = activeSection === "network";
  const isInvestigation = activeSection === "investigation";
  const isReports = activeSection === "reports";
  const isSettings = activeSection === "settings";

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
          <a href="#dashboard" className={`sidebar-item ${isDashboard ? "active" : ""}`}>
            <span>▣</span> Dashboard
          </a>
          <a href="#events" className={`sidebar-item ${isEvents ? "active" : ""}`}>
            <span>◉</span> Live Events
          </a>
          <a href="#alerts" className={`sidebar-item ${isAlerts ? "active" : ""}`}>
            <span>⚠</span> Security Alerts
          </a>
          <a href="#alert-management" className={`sidebar-item ${isAlertManagement ? "active" : ""}`}>
            <span>☑</span> Alert Management
          </a>
          <a href="#incidents" className={`sidebar-item ${isIncidents ? "active" : ""}`}>
            <span>🧾</span> Incident Management
          </a>
          <a href="#hosts" className={`sidebar-item ${isHosts ? "active" : ""}`}>
            <span>🖥️</span> Host Monitoring
          </a>
          <a href="#threat-intelligence" className={`sidebar-item ${isThreatIntel ? "active" : ""}`}>
            <span>🌐</span> Threat Intelligence
          </a>
          <a href="#ueba" className={`sidebar-item ${isUeba ? "active" : ""}`}>
            <span>◈</span> UEBA Analysis
          </a>
          <a href="#network" className={`sidebar-item ${isNetwork ? "active" : ""}`}>
            <span>⌘</span> Network Topology
          </a>
          <a href="#investigation" className={`sidebar-item ${isInvestigation ? "active" : ""}`}>
            <span>⌕</span> Investigation
          </a>
          <a href="#reports" className={`sidebar-item ${isReports ? "active" : ""}`}>
            <span>▤</span> Reports
          </a>
          <a href="#settings" className={`sidebar-item ${isSettings ? "active" : ""}`}>
            <span>⚙</span> Settings
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
          TOP BAR
      ================================================== */}
      <header className="topbar">
        <div className="topbar-brand">
          <div className="topbar-title-row">
            <span className="topbar-shield">🛡️</span>
            <div>
              <h1>SIEM SOC COMMAND CENTER</h1>
              <p>Real-Time Security Monitoring & Threat Detection</p>
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
              onChange={(event) => setSearchTerm(event.target.value)}
            />
            {searchTerm && (
              <button className="search-clear" onClick={() => setSearchTerm("")} aria-label="Clear search">×</button>
            )}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "#cbd5e1", fontSize: "13px" }}>
            <span>{currentUser?.username || "admin"}</span>
            <button onClick={logout} title="Sign out">Logout</button>
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

      {/* ==================================================
          ROUTED MAIN CONTENT
      ================================================== */}
      <main className="dashboard">

        {/* 1. DASHBOARD OVERVIEW */}
        {isDashboard && (
          <>
            <section className="stats">
              <div className="card">
                <h3>Total Events</h3>
                <strong>{totalEvents}</strong>
                <span>Security events received</span>
              </div>
              <div className="card danger">
                <h3>Threats Detected</h3>
                <strong>{threatsDetected}</strong>
                <span>Potential threats detected</span>
              </div>
              <div className="card warning">
                <h3>Failed Logins</h3>
                <strong>{failedLogins}</strong>
                <span>Authentication failures</span>
              </div>
              <div className="card danger">
                <h3>High Severity Alerts</h3>
                <strong>{highSeverityAlerts}</strong>
                <span>Critical security alerts</span>
              </div>
            </section>

            {/* SOC THREAT LEVEL */}
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
                  <h2 style={{ margin: 0, color: "#f8fafc", fontSize: "22px", fontWeight: 800 }}>
                    🛡️ Threat Level
                  </h2>
                  <p style={{ margin: "7px 0 0", color: "#94a3b8", fontSize: "14px" }}>
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
                        threatLevel === "CRITICAL" ? "#ef4444" : threatLevel === "HIGH" ? "#f97316" : threatLevel === "MEDIUM" ? "#eab308" : "#22c55e",
                      boxShadow:
                        threatLevel === "CRITICAL" ? "0 0 12px #ef4444" : threatLevel === "HIGH" ? "0 0 12px #f97316" : threatLevel === "MEDIUM" ? "0 0 12px #eab308" : "0 0 12px #22c55e",
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
                      ${threatLevel === "CRITICAL" ? "#ef4444" : threatLevel === "HIGH" ? "#f97316" : threatLevel === "MEDIUM" ? "#eab308" : "#22c55e"} ${Math.max(threatScore, 4)}%,
                      #1e293b ${Math.max(threatScore, 4)}%
                    )`,
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
                    <strong style={{ fontSize: "42px", lineHeight: 1, color: "#f8fafc", fontWeight: 900 }}>
                      {threatScore}
                    </strong>
                    <span style={{ marginTop: "5px", color: "#64748b", fontSize: "13px" }}>/ 100</span>
                    <small
                      style={{
                        marginTop: "8px",
                        color:
                          threatLevel === "CRITICAL" ? "#ef4444" : threatLevel === "HIGH" ? "#f97316" : threatLevel === "MEDIUM" ? "#eab308" : "#22c55e",
                        fontSize: "13px",
                        fontWeight: 900,
                        letterSpacing: "1px",
                      }}
                    >
                      {threatLevel}
                    </small>
                  </div>
                </div>

                <div className="threat-breakdown" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
                  {[
                    { name: "Critical", count: criticalThreats, color: "#ef4444", bg: "rgba(239,68,68,0.10)" },
                    { name: "High", count: highThreats, color: "#f97316", bg: "rgba(249,115,22,0.10)" },
                    { name: "Medium", count: mediumThreats, color: "#eab308", bg: "rgba(234,179,8,0.10)" },
                    { name: "Low", count: lowThreats, color: "#22c55e", bg: "rgba(34,197,94,0.10)" },
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
                      <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
                        <strong style={{ color: "#f8fafc", fontSize: "25px", lineHeight: 1 }}>{item.count}</strong>
                        <span style={{ color: "#94a3b8", fontSize: "13px" }}>{item.name}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            {/* 3D NETWORK PREVIEW */}
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>🌐 Monitored Network Topology</h2>
                  <p>Real-time monitored host network visualization</p>
                </div>
              </div>
              <Network3D />
            </section>
          </>
        )}

        {/* 2. HOST MONITORING */}
        {(isHosts || isDashboard) && (
          <section className="panel" id="hosts">
            <div className="panel-header">
              <div>
                <h2>💻 Monitored Hosts</h2>
                <p>Host activity, failed-login risk and status from the last 24 hours</p>
              </div>
              <button onClick={fetchHosts}>↻ Refresh Hosts</button>
            </div>

            <div className="stats">
              <div className="card">
                <h3>Total Hosts</h3>
                <strong>{hosts.length}</strong>
                <span>Hosts known to Elasticsearch</span>
              </div>

              {hosts.map((host, index) => {
                const hostname = host.hostname || `Unknown host ${index + 1}`;
                const status = String(host.status || "NORMAL").toUpperCase();
                const severity = String(host.severity || "LOW").toUpperCase();
                const riskScore = Number.isFinite(Number(host.risk_score)) ? Number(host.risk_score) : 0;
                const isSimulation = Boolean(host.simulation_only);
                const statusColor = status === "CRITICAL" ? "#f87171" : status === "WARNING" ? "#facc15" : "#4ade80";
                const severityColor = severity === "CRITICAL" ? "#f87171" : severity === "HIGH" ? "#fb923c" : severity === "MEDIUM" ? "#facc15" : "#4ade80";

                return (
                  <div className="card" key={`${hostname}-${index}`} style={{ minWidth: "220px" }}>
                    <h3 style={{ overflowWrap: "anywhere" }}>🖥️ {hostname}</h3>
                    {isSimulation && (
                      <span style={{ display: "inline-block", width: "fit-content", margin: "4px 0 10px", padding: "4px 8px", borderRadius: "6px", color: "#facc15", background: "rgba(234,179,8,.12)", border: "1px solid rgba(234,179,8,.4)", fontSize: "11px", fontWeight: 800 }}>
                        SIMULATION ONLY
                      </span>
                    )}

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginTop: "12px" }}>
                      <div>
                        <small style={{ display: "block", color: "#94a3b8" }}>Events (24h)</small>
                        <strong style={{ fontSize: "22px" }}>{host.event_count ?? 0}</strong>
                      </div>
                      <div>
                        <small style={{ display: "block", color: "#94a3b8" }}>Risk score</small>
                        <strong style={{ fontSize: "22px" }}>{riskScore}<small style={{ fontSize: "12px", color: "#94a3b8" }}> / 100</small></strong>
                      </div>
                      <div>
                        <small style={{ display: "block", color: "#94a3b8" }}>Failed logins</small>
                        <strong>{host.failed_login_count ?? 0}</strong>
                      </div>
                      <div>
                        <small style={{ display: "block", color: "#94a3b8" }}>Real failed logins</small>
                        <strong>{host.real_failed_login_count ?? 0}</strong>
                      </div>
                      <div>
                        <small style={{ display: "block", color: "#94a3b8" }}>Simulation failures</small>
                        <strong>{host.simulation_failed_login_count ?? 0}</strong>
                      </div>
                      <div>
                        <small style={{ display: "block", color: "#94a3b8" }}>Threat count</small>
                        <strong>{host.threat_count ?? 0}</strong>
                      </div>
                    </div>

                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "16px" }}>
                      <span style={{ padding: "5px 9px", borderRadius: "999px", color: severityColor, background: `${severityColor}18`, border: `1px solid ${severityColor}66`, fontSize: "11px", fontWeight: 800 }}>
                        {severity}
                      </span>
                      <span style={{ padding: "5px 9px", borderRadius: "999px", color: statusColor, background: `${statusColor}18`, border: `1px solid ${statusColor}66`, fontSize: "11px", fontWeight: 800 }}>
                        {status}
                      </span>
                    </div>
                    {isSimulation && (
                      <p style={{ margin: "10px 0 0", color: "#facc15", fontSize: "11px" }}>Synthetic test activity is not evidence of a real attack.</p>
                    )}
                  </div>
                );
              })}
            </div>

            {hosts.length === 0 && (
              <p style={{ padding: "20px", color: "#94a3b8" }}>No monitored hosts were returned by the backend.</p>
            )}
          </section>
        )}

        {/* 3. SECURITY ANALYTICS */}
        {(isDashboard || isHosts) && (
          <section className="panel">
            <div className="panel-header">
              <div>
                <h2>📊 Security Analytics</h2>
                <p>Security activity from the last 24 hours</p>
              </div>
              <button onClick={() => fetchAnalytics()}>Refresh Analytics</button>
            </div>

            {analyticsLoading && <p style={{ padding: "20px" }}>Loading security analytics...</p>}
            {analyticsError && <p style={{ padding: "20px", color: "#f87171" }}>{analyticsError}</p>}
            {!analyticsLoading && !analyticsError && analytics && (
              <>
                <div className="stats">
                  <div className="card">
                    <h3>Total Events</h3>
                    <strong>{analytics.total_events}</strong>
                    <span>Last 24 hours</span>
                  </div>
                  <div className="card warning">
                    <h3>Failed Logins</h3>
                    <strong>{analytics.failed_logins}</strong>
                    <span>Authentication failures</span>
                  </div>
                  <div className="card">
                    <h3>Successful Logins</h3>
                    <strong>{analytics.successful_logins}</strong>
                    <span>Authentication successes</span>
                  </div>
                  <div className="card danger">
                    <h3>Threat Events</h3>
                    <strong>{analytics.threat_events}</strong>
                    <span>Detected security threats</span>
                  </div>
                </div>

                <div className="analytics-grid">
                  <div className="panel">
                    <div style={{ padding: "22px" }}>
                      <h3>⚠️ Severity Distribution</h3>
                      <div className="severity-list">
                        {[
                          { key: "CRITICAL", label: "🔴 CRITICAL", cls: "severity-critical" },
                          { key: "HIGH", label: "🟠 HIGH", cls: "severity-high" },
                          { key: "MEDIUM", label: "🟡 MEDIUM", cls: "severity-medium" },
                          { key: "LOW", label: "🟢 LOW", cls: "severity-low" },
                        ].map((sev) => {
                          const count = analytics.severity_distribution?.[sev.key] || 0;
                          const pct = analytics.total_events > 0 ? (count / analytics.total_events) * 100 : 0;
                          return (
                            <div className="severity-row" key={sev.key}>
                              <div className="severity-label">
                                <span>{sev.label}</span>
                                <strong>{count}</strong>
                              </div>
                              <div className="severity-bar">
                                <div className={`severity-fill ${sev.cls}`} style={{ width: `${pct}%` }} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>

                  <div className="panel">
                    <div style={{ padding: "22px" }}>
                      <h3>🌐 Top Source IPs</h3>
                      <div className="table-container" style={{ marginTop: "15px" }}>
                        {topSourceIPs.length > 0 ? (
                          <table>
                            <thead>
                              <tr><th>Source IP</th><th>Events</th></tr>
                            </thead>
                            <tbody>
                              {topSourceIPs.map((ip, index) => (
                                <tr key={`${String(ip.source_ip)}-${index}`}>
                                  <td>
                                    <div className="ip-display" style={{ display: "flex", alignItems: "center", gap: "12px", marginRight: "12px" }}>
                                      <span className="ip-rank" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: "28px", height: "28px", marginRight: "0", flexShrink: 0 }}>
                                        {index + 1}
                                      </span>
                                      <strong className="ip-address" title={String(ip.source_ip)} style={{ display: "inline-block", whiteSpace: "normal", overflowWrap: "anywhere", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" }}>
                                        {formatSourceIP(ip.source_ip)}
                                      </strong>
                                    </div>
                                  </td>
                                  <td><span className="ip-count">{ip.event_count}</span></td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        ) : (
                          <p style={{ padding: "20px" }}>No source IP activity detected.</p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </>
            )}
          </section>
        )}

        {/* 4. LIVE EVENTS */}
        {(isEvents || isDashboard) && (
          <section className="panel" id="events">
            <div className="panel-header">
              <div>
                <h2>Recent Security Events</h2>
                <p>{searchTerm ? `Showing ${filteredEvents.length} matching event(s)` : "Latest events received from monitored systems"}</p>
              </div>
              <button onClick={() => fetchEvents()}>Refresh</button>
            </div>

            {loading && <p style={{ padding: "20px" }}>Loading security events...</p>}
            {error && <p style={{ padding: "20px", color: "#f87171" }}>{error}</p>}
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
                          severity === "CRITICAL" ? "severity-critical" : severity === "HIGH" ? "severity-high" : severity === "MEDIUM" ? "severity-medium" : severity === "LOW" ? "severity-low" : "badge";
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
        )}

        {/* 5. SECURITY ALERTS */}
        {(isAlerts || isDashboard) && (
          <section className="panel alerts-panel" id="alerts">
            <div className="panel-header">
              <div>
                <h2>🚨 Security Alerts</h2>
                <p>Detected threats from the last 5 minutes</p>
              </div>
              <button onClick={() => fetchAlerts()}>Refresh Alerts</button>
            </div>

            {alertsLoading && <p style={{ padding: "20px" }}>Loading security alerts...</p>}
            {alertsError && <p style={{ padding: "20px", color: "#f87171" }}>{alertsError}</p>}
            {!alertsLoading && !alertsError && (
              <div className="table-container">
                {alerts.length === 0 ? (
                  <p style={{ padding: "20px" }}>No active security alerts.</p>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Alert</th>
                        <th>Threat Type</th>
                        <th>Severity</th>
                        <th>Risk Score</th>
                        <th>Username</th>
                        <th>Source IP</th>
                        <th>IP Reputation</th>
                        <th>Time</th>
                        <th>Investigation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.map((alert, index) => (
                        <tr key={`${alert.source_ip}-${alert["@timestamp"]}-${index}`}>
                          <td><span className="alert-badge">🚨 {alert.alert}</span></td>
                          <td className="threat">{alert.threat_type || "-"}</td>
                          <td><span className="severity-high">{alert.severity}</span></td>
                          <td><strong>{alert.risk_score}</strong></td>
                          <td>{alert.username || "-"}</td>
                          <td>{alert.source_ip || "-"}</td>
                          <td>{renderIPReputation(alert)}</td>
                          <td>{alert["@timestamp"] ? new Date(alert["@timestamp"]).toLocaleTimeString() : "-"}</td>
                          <td>
                            <button onClick={() => { investigateIP(alert.source_ip); window.location.hash = "investigation"; }}>
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
        )}

        {/* 6. ALERT MANAGEMENT */}
        {(isAlertManagement || isDashboard) && (
          <section className="panel" id="alert-management">
            <div className="panel-header">
              <div>
                <h2>🗂️ Alert Management</h2>
                <p>Review historical alerts and acknowledge or resolve incidents</p>
              </div>
              <button onClick={() => fetchAlertHistory()} disabled={historyLoading}>
                {historyLoading ? "Loading..." : "↻ Refresh History"}
              </button>
            </div>

            <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", padding: "0 20px 18px" }}>
              <input
                value={historySearch}
                onChange={(event) => {
                  const nextSearch = event.target.value;
                  setHistorySearch(nextSearch);
                  historySearchRef.current = nextSearch;
                  setHistoryPage(0);
                  historyPageRef.current = 0;
                  if (historySearchTimerRef.current) clearTimeout(historySearchTimerRef.current);
                  historySearchTimerRef.current = setTimeout(() => {
                    historySearchTimerRef.current = null;
                    fetchAlertHistory(0, historyStatusFilter, nextSearch, historySeverityFilter);
                  }, 350);
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    if (historySearchTimerRef.current) clearTimeout(historySearchTimerRef.current);
                    historySearchTimerRef.current = null;
                    fetchAlertHistory(0, historyStatusFilter, historySearch, historySeverityFilter);
                  }
                }}
                placeholder="Search all historical alerts: alert, username, IP, or host..."
                style={{ minWidth: "230px", flex: "1", padding: "10px 12px", borderRadius: "8px", border: "1px solid #294768", background: "#081525", color: "#e2e8f0" }}
              />
              <select
                value={historyStatusFilter}
                onChange={(event) => {
                  const nextStatus = event.target.value;
                  setHistoryStatusFilter(nextStatus);
                  historyStatusFilterRef.current = nextStatus;
                  setHistoryPage(0);
                  historyPageRef.current = 0;
                  fetchAlertHistory(0, nextStatus, historySearch, historySeverityFilter);
                }}
                style={{ padding: "10px", borderRadius: "8px", background: "#081525", color: "#e2e8f0", border: "1px solid #294768" }}
              >
                <option value="ALL">All statuses</option>
                <option value="OPEN">OPEN</option>
                <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                <option value="RESOLVED">RESOLVED</option>
              </select>
              <select
                value={historySeverityFilter}
                onChange={(event) => {
                  const nextSeverity = event.target.value;
                  setHistorySeverityFilter(nextSeverity);
                  historySeverityFilterRef.current = nextSeverity;
                  setHistoryPage(0);
                  historyPageRef.current = 0;
                  fetchAlertHistory(0, historyStatusFilter, historySearch, nextSeverity);
                }}
                style={{ padding: "10px", borderRadius: "8px", background: "#081525", color: "#e2e8f0", border: "1px solid #294768" }}
              >
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
              <div className="table-container">
                {alertHistory.length === 0 ? (
                  <p style={{ padding: "20px" }}>No alerts match these filters.</p>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Alert</th><th>Severity</th><th>Risk</th><th>User</th><th>Source IP</th><th>Time</th><th>Status</th><th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alertHistory.map((item, index) => {
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
            )}

            <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: "12px", padding: "16px 20px", borderTop: "1px solid #243b5a" }}>
              <span style={{ color: "#94a3b8", fontSize: "13px" }}>
                Showing {historyTotal === 0 ? 0 : historyPage * historyPageSize + 1}–{Math.min((historyPage + 1) * historyPageSize, historyTotal)} of {historyTotal} alerts
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <button
                  onClick={() => {
                    const nextPage = Math.max(0, historyPage - 1);
                    historyPageRef.current = nextPage;
                    fetchAlertHistory(nextPage);
                  }}
                  disabled={historyLoading || Boolean(historySearchTimerRef.current) || historyPage === 0}
                >
                  ← Previous
                </button>
                <span style={{ color: "#cbd5e1", fontSize: "13px" }}>
                  Page {historyTotal === 0 ? 0 : historyPage + 1} of {Math.max(1, Math.ceil(historyTotal / historyPageSize))}
                </span>
                <button
                  onClick={() => {
                    const nextPage = historyPage + 1;
                    historyPageRef.current = nextPage;
                    fetchAlertHistory(nextPage);
                  }}
                  disabled={historyLoading || Boolean(historySearchTimerRef.current) || (historyPage + 1) * historyPageSize >= historyTotal}
                >
                  Next →
                </button>
              </div>
            </div>
          </section>
        )}

        {/* 7. INCIDENT MANAGEMENT */}
        {(isIncidents || isDashboard) && (
          <section className="panel" id="incidents">
            <div className="panel-header">
              <div>
                <h2>🧾 Incident Management</h2>
                <p>Track security incidents, assign analysts, update workflow status and record investigation notes.</p>
              </div>
              <button onClick={() => fetchIncidents()} disabled={incidentsLoading}>
                {incidentsLoading ? "Loading..." : "↻ Refresh Incidents"}
              </button>
            </div>

            <div className="stats" style={{ padding: "18px 20px" }}>
              <div className="card"><h3>Total Incidents</h3><strong>{incidents.length}</strong><span>Recorded incidents</span></div>
              <div className="card warning"><h3>Open</h3><strong>{incidents.filter((i) => i.status === "OPEN").length}</strong><span>Awaiting investigation</span></div>
              <div className="card danger"><h3>Investigating</h3><strong>{incidents.filter((i) => i.status === "INVESTIGATING").length}</strong><span>Under analyst review</span></div>
              <div className="card"><h3>Resolved</h3><strong>{incidents.filter((i) => i.status === "RESOLVED").length}</strong><span>Closed incidents</span></div>
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
                                  {(incident.notes || []).length === 0 ? <p>No notes added yet.</p> : (incident.notes || []).map((note, idx) => (
                                    <div key={`${note.created_at || idx}`} style={{ padding: "10px", border: "1px solid #294768", borderRadius: "8px" }}>
                                      <p style={{ margin: "0 0 6px" }}>{note.note}</p>
                                      <small style={{ color: "#94a3b8" }}>{note.author || "Unknown"} · {note.created_at ? new Date(note.created_at).toLocaleString() : ""}</small>
                                    </div>
                                  ))}
                                  <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                                    <input value={incidentNoteDrafts[id] || ""} onChange={(e) => setIncidentNoteDrafts((cur) => ({ ...cur, [id]: e.target.value }))}
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
        )}

        {/* 8. THREAT INTELLIGENCE / IP MONITORING */}
        {(isThreatIntel || isDashboard) && (
          <section className="panel" id="threat-intelligence">
            <div className="panel-header">
              <div>
                <h2>🌐 Threat Intelligence & IP Monitoring</h2>
                <p>Source IP activity and threat risk from the last 24 hours</p>
              </div>
              <button onClick={() => fetchIPMonitoring()}>Refresh IPs</button>
            </div>

            {ipLoading && <p style={{ padding: "20px" }}>Loading IP monitoring data...</p>}
            {ipError && <p style={{ padding: "20px", color: "#f87171" }}>{ipError}</p>}
            {!ipLoading && !ipError && (
              <div className="table-container">
                {ipMonitoring.length === 0 ? (
                  <p style={{ padding: "20px" }}>No IP activity detected in the last 24 hours.</p>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>Source IP</th><th>Failed Logins</th><th>Successful Logins</th><th>Total Events</th><th>Risk Score</th><th>Severity</th><th>Status</th><th>Investigation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ipMonitoring.map((ip) => (
                        <tr key={ip.source_ip}>
                          <td><strong>{ip.source_ip}</strong></td>
                          <td>{ip.failed_logins}</td>
                          <td>{ip.successful_logins}</td>
                          <td>{ip.total_events}</td>
                          <td><strong>{ip.risk_score}</strong></td>
                          <td><span className="severity-high">{ip.severity}</span></td>
                          <td><span className="alert-badge">{ip.status}</span></td>
                          <td>
                            <button onClick={() => { investigateIP(ip.source_ip); window.location.hash = "investigation"; }}>
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
        )}

        {/* 9. UEBA ANALYSIS */}
        {(isUeba || isDashboard) && (
          <section className="panel" id="ueba">
            <div className="panel-header">
              <div>
                <h2>🧠 UEBA Analysis</h2>
                <p>User and Entity Behavior Analytics — anomalies identified by the backend</p>
              </div>
              <button onClick={() => fetchAlerts()}>Refresh UEBA</button>
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
                    <p style={{ padding: "20px" }}>No active UEBA alerts returned by the backend.</p>
                  ) : (
                    <table>
                      <thead>
                        <tr>
                          <th>Entity</th><th>Entity Type</th><th>IP Reputation</th><th>Anomaly</th><th>Severity</th><th>Risk</th><th>Activity</th><th>Failed Logins</th><th>Baseline</th><th>Detection Reason</th>
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
                              <td>{alert.entity_type === "IP" || alert.source_ip ? renderIPReputation(alert) : <span style={{ color: "#64748b" }}>N/A</span>}</td>
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
              </>
            )}
          </section>
        )}

        {/* 10. NETWORK TOPOLOGY */}
        {isNetwork && (
          <section className="panel" id="network">
            <div className="panel-header">
              <div>
                <h2>🌐 3D Network Topology</h2>
                <p>Real-time monitored host network visualization</p>
              </div>
            </div>
            <Network3D />
          </section>
        )}

        {/* 11. THREAT INVESTIGATION */}
        {(isInvestigation || isDashboard) && (
          <section className="panel" id="investigation">
            <div className="panel-header">
              <div>
                <h2>🔎 Threat Investigation</h2>
                <p>Enter a source IP address to retrieve its related security events.</p>
              </div>
            </div>

            <form
              onSubmit={(event) => {
                event.preventDefault();
                investigateIP(investigationIP);
              }}
              style={{ display: "flex", flexWrap: "wrap", gap: "12px", padding: "20px", alignItems: "center" }}
            >
              <input
                type="text"
                value={investigationIP}
                onChange={(event) => setInvestigationIP(event.target.value)}
                placeholder="Enter source IP (e.g. 198.51.100.25)"
                aria-label="Source IP address"
                style={{ flex: "1", minWidth: "240px", padding: "12px 14px", borderRadius: "8px", border: "1px solid #294768", background: "#081525", color: "#e2e8f0" }}
              />
              <button type="submit" disabled={investigating}>
                {investigating ? "Investigating..." : "🔎 Investigate IP"}
              </button>
            </form>

            {investigationError && (
              <p role="alert" style={{ margin: "0 20px 18px", padding: "12px", color: "#fca5a5", background: "rgba(127, 29, 29, 0.2)", border: "1px solid rgba(248, 113, 113, 0.35)", borderRadius: "8px" }}>
                {investigationError}
              </p>
            )}

            {investigating && (
              <p style={{ padding: "0 20px 20px", color: "#7dd3fc" }}>🔎 Searching security events for {investigationIP}...</p>
            )}

            {investigation && !investigating && (
              <>
                <div className="stats" style={{ padding: "0 20px 20px" }}>
                  <div className="card"><h3>Source IP</h3><strong style={{ fontSize: "18px", overflowWrap: "anywhere" }}>{investigation.source_ip || investigationIP}</strong><span>Investigated address</span></div>
                  <div className="card danger"><h3>Related Events</h3><strong>{investigation.total_events ?? (investigation.events || []).length}</strong><span>Events returned by backend</span></div>
                </div>

                <div className="table-container" style={{ overflowX: "auto" }}>
                  {(Array.isArray(investigation.events) && investigation.events.length > 0) ? (
                    <table>
                      <thead><tr><th>Event Type</th><th>Event ID</th><th>Username</th><th>Source IP</th><th>Host</th><th>Message</th><th>Time</th></tr></thead>
                      <tbody>
                        {investigation.events.map((event, index) => (
                          <tr key={event.id || `${event.event_id || event.winlog?.event_id || "event"}-${event["@timestamp"] || index}`}>
                            <td>{Array.isArray(event.event_type) ? event.event_type.join(", ") : (event.event_type || "security_event")}</td>
                            <td>{event.winlog?.event_id || event.event?.code || event.event_id || "-"}</td>
                            <td>{event.username || event.user?.name || event.winlog?.event_data?.TargetUserName || "-"}</td>
                            <td>{event.source_ip || event.source?.ip || investigation.source_ip || "-"}</td>
                            <td>{event.host?.hostname || event.host?.name || event.hostname || "-"}</td>
                            <td style={{ minWidth: "240px", whiteSpace: "normal", overflowWrap: "anywhere" }}>{event.message || "-"}</td>
                            <td>{event["@timestamp"] ? new Date(event["@timestamp"]).toLocaleString() : "-"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p style={{ padding: "20px" }}>No related events were returned for this IP address.</p>
                  )}
                </div>
              </>
            )}
          </section>
        )}

        {/* 12. REPORTS */}
        {(isReports || isDashboard) && (
          <section className="panel" id="reports">
            <div className="panel-header">
              <div>
                <h2>📄 Security Reports</h2>
                <p>Review current SIEM activity and export records for further analysis.</p>
              </div>
              <button onClick={() => window.print()}>Print Report</button>
            </div>
            <div className="stats" style={{ padding: "20px" }}>
              <div className="card"><h3>Events Loaded</h3><strong>{totalEvents}</strong><span>Events currently available</span></div>
              <div className="card danger"><h3>Detected Threats</h3><strong>{threatsDetected}</strong><span>Threat-tagged events</span></div>
              <div className="card warning"><h3>Failed Logins</h3><strong>{failedLogins}</strong><span>Failed authentication events</span></div>
              <div className="card"><h3>Historical Alerts</h3><strong>{alertHistory.length}</strong><span>Records in alert history</span></div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", padding: "0 20px 20px" }}>
              <button onClick={() => downloadReport("events")}>⬇ Export Events (CSV)</button>
              <button onClick={() => downloadReport("alerts")}>⬇ Export Alert History (CSV)</button>
              <button onClick={() => { fetchEvents(); fetchAlertHistory(); fetchAnalytics(); }}>↻ Refresh Report Data</button>
            </div>
          </section>
        )}

        {/* 13. SETTINGS */}
        {(isSettings || isDashboard) && (
          <section className="panel" id="settings">
            <div className="panel-header">
              <div>
                <h2>⚙️ Settings</h2>
                <p>Application information, account session, and quick maintenance actions.</p>
              </div>
            </div>
            <div className="stats" style={{ padding: "20px" }}>
              <div className="card"><h3>Application</h3><strong>SIEM v1.0</strong><span>Security Operations Center</span></div>
              <div className="card"><h3>Backend API</h3><strong style={{ fontSize: "16px" }}>{API_URL}</strong><span>Configured backend endpoint</span></div>
              <div className="card"><h3>Signed-in User</h3><strong>{currentUser?.username || "admin"}</strong><span>Authenticated session</span></div>
              <div className="card"><h3>Session Status</h3><strong style={{ color: "#4ade80" }}>● Active</strong><span>Authenticated</span></div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", padding: "0 20px 20px" }}>
              <button onClick={() => { fetchEvents(); fetchAlerts(); fetchAlertHistory(); fetchIncidents(); fetchIPMonitoring(); fetchAnalytics(); fetchHosts(); }}>↻ Refresh All SIEM Data</button>
              <button onClick={logout} style={{ background: "#b91c1c" }}>⇥ Sign Out</button>
            </div>
          </section>
        )}

      </main>

      {/* MODAL: EVENT DETAILS */}
      {selectedEvent && (
        <div onClick={() => setSelectedEvent(null)} style={{ position: "fixed", inset: 0, zIndex: 9999, background: "rgba(2, 6, 23, 0.78)", backdropFilter: "blur(6px)", display: "flex", alignItems: "center", justifyContent: "center", padding: "24px" }}>
          <div onClick={(e) => e.stopPropagation()} style={{ width: "min(900px, 100%)", maxHeight: "85vh", overflowY: "auto", background: "linear-gradient(145deg, #0f1b31 0%, #08111f 100%)", border: "1px solid #294768", borderRadius: "16px", boxShadow: "0 25px 80px rgba(0, 0, 0, 0.55)", padding: "24px" }}>
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
    </div>
  );
}

export default App;