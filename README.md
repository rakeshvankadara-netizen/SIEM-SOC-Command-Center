# Real-Time SIEM SOC Command Center

An enterprise-grade Security Information and Event Management (SIEM) and Security Operations Center (SOC) platform designed for high-throughput log ingestion, real-time threat detection, User and Entity Behavior Analytics (UEBA), and incident response.

---

## Key Features

* **Real-Time Stream Processing:** Ingestion and normalization of Windows Security Events (IDs 4624, 4625, 4672).
* **Multi-Stage Threat Correlation:** Automated detection for Brute-Force, Port Scanning, and multi-step Attack Chains.
* **Behavioral Analytics (UEBA):** 7-day rolling statistical baselines to catch unusual user logins and anomalous behavior.
* **3D Network Topology:** Interactive Three.js canvas visualizing endpoint health and security alerts across hosts.
* **Incident Management:** Incident ticketing, severity scoring, threat notes, and CSV compliance reports.

---

## Tech Stack

* **Backend:** FastAPI (Python), Uvicorn, Elasticsearch-py, JWT Authentication, WebSockets
* **Data Store:** Elasticsearch 8.x
* **Frontend:** React, Vite, Three.js, Lucide Icons
* **Log Shipper:** Filebeat & Logstash

---

## How to Run Locally

### 1. Start Elasticsearch
Make sure Elasticsearch is running on `http://127.0.0.1:9200`.

### 2. Start Backend
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8001 --reload
### 3. Start Frontend
```bash
cd frontend
npm install
npm run dev
