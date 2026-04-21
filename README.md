# ANTI-HPE: Enterprise Network Threat Detection Pipeline

![HPE Threat Dashboard](frontend/public/favicon.ico) <!-- Placeholder, replace with real screenshot if available later -->

ANTI-HPE is a production-grade, AI-powered cybersecurity threat detection pipeline. It simulates a modern Security Operations Center (SOC) backend and visualizes real-time network traffic interceptions via a stunning 3D WebGL interface and a Structural Spatial (Bento Box) dashboard.

## Overview

The system is designed to ingest raw network traffic, extract behavioral features, execute high-speed machine learning inference in a microservice backend, and trigger automated orchestrated responses (like HashiCorp Vault credential rotation) when a zero-day or malicious pattern is detected.

### The Pipeline Architecture
The dashboard visually maps and documents an enterprise-grade 10-stage pipeline:
1. **Network / Apps:** PCAP capture & eBPF tracing tools collect network telemetry.
2. **Zeek / Suricata:** Deep Packet Inspection (DPI) intrusion detection.
3. **Elastic Beats:** Elastic Common Schema (ECS) normalization & GeoIP enrichment.
4. **Apache Kafka:** KRaft mode event streaming broker for high throughput.
5. **AI Engine:** FastAPI microservice utilizing a Soft-Voting Ensemble (XGBoost + LightGBM + Isolation Forest).
6. **SOAR:** Security Orchestration, Automation, and Response workflow triggering.
7. **HashiCorp Vault:** Dynamic secret management API.
8. **Credential Rotation:** Cryptographically secure revocation of compromised sessions.
9. **Distribution:** Secure automated pushing of new tokens to internal microservices via TLS 1.3.
10. **ELK/Grafana:** Elasticsearch persistent indexing and Kibana visual analytics.

## Technologies Used

* **Frontend:** Vanilla JavaScript, Vite, HTML5, CSS3 (Structural Cyber-Bento styling).
* **3D Visualization:** `three-globe` / `globe.gl` (WebGL-accelerated geospatial projections).
* **Backend:** Python 3.10+, FastAPI (Asynchronous API and WebSockets).
* **Machine Learning:** `scikit-learn`, `xgboost`, `lightgbm` (Feature Engineering and Ensembling).
* **Infrastructure Layer:** Docker Compose (Kafka, Zookeeper/KRaft, Elasticsearch, HashiCorp Vault).

## Project Setup

The project is split into a Python Backend and a Vite Frontend.

### 1. Backend Setup

The core AI engine and WebSocket simulation server runs on FastAPI.

```bash
cd backend

# Create a virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --reload --port 8000
```

*Note: For the full production stack involving Kafka and ELK, utilize the provided `docker-compose.yml` (e.g., `docker-compose up -d --build`). Ensure Docker has sufficient memory allocated (minimum 8GB recommended for the ELK stack).*

### 2. Frontend Setup

The visual dashboard connects to the backend to display the 3D globe and metrics.

```bash
cd frontend

# Install Node modules
npm install

# Start the Vite development server
npm run dev
```

*The frontend will automatically proxy `/api` and `/ws` requests to the locally running FastAPI backend at port 8000.*

## UI / UX Features

* **3D Threat Globe:** An interactive WebGL globe. Hover over network lines to smartly pause rotation, and click active paths to inspect technical metadata (source, destination, threat threshold, and target processes).
* **Spatial 'Bento' Design:** The dashboard has been engineered utilizing 2026 strict Spatial UI rules—flat opaque Zinc panels, sharp `8px` borders, brutalist layout constraints, and zero blurry gradients ensuring high FPS. 
* **Live Incident Explanations:** The interactive 10-stage pipeline exposes dense technical explanations of what happens to a socket layer packet as it traverses an enterprise security array.
* **Vault Credential Rotater:** When a critical threshold anomaly is captured, a HashiCorp Vault terminal automatically slides in, simulating an emergency cryptographic revocation sequence.

## Team
HPE Code Project Interns
