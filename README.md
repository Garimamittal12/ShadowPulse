# ShadowPulse - Real-Time MITM Attack Detection System

ShadowPulse is a real-time network monitoring and MITM detection project. Its FastAPI backend captures packets through one shared Scapy `PacketDispatcher`, runs the enabled detectors, stores alerts and network observations in SQLite, and serves data to a React dashboard. The dashboard receives alert and device events over WebSocket and refreshes REST snapshots every 30 seconds. Detection is heuristic: an alert is evidence to investigate, not proof of a confirmed attack.

---

## Features

### Detection Engine (Backend)
- **Packet capture** using `scapy` with pluggable detector modules
- **7 built-in detectors** covering common Layer-2/3/4/7 attacks 
- **SQLite persistence** of alerts, devices, and detector status
- **Configurable monitoring** via `shadowpulse.conf` and environment variables
- **One centralized Scapy capture dispatcher** shared by all detector modules

### Dashboard (Frontend)
- **Live monitoring** with WebSocket alert/device events and REST recovery refresh
- **Attack analytics** with charts, severity breakdowns, and trend heatmaps
- **Network topology** view of discovered devices and suspicious hosts
- **Rogue Access Point** monitor (evil-twin / SSID impersonation detection)
- **SSL Strip monitor** (HTTPS downgrade / HSTS-bypass detection)
- **Alert history** in the dashboard, with a separate API for stored network logs
- **Dark / light theme** toggle and real-time critical-alert toasts

---

## Tech Stack

| Layer | Technology | Port |
|-------|-----------|------|
| Backend API | Python 3.10+ / FastAPI / Uvicorn | `5000` |
| Database | SQLite | file `shadowpulse.db` |
| Packet Capture | Scapy | - |
| Frontend | React 18 / TypeScript / Vite / Tailwind CSS | `5173` by default |
| Charts | Recharts | - |
| Icons | lucide-react | - |

---
## Prerequisites

- **Python 3.10+**
- **Node.js 18+** and **npm**
- A network interface to capture traffic (for live detection). On **Linux/macOS** packet capture typically requires root/admin privileges or `libpcap`; on **Windows**, use Npcap with the `scapy` backend.

---

## Windows/Npcap Verification Guide

For live packet capture on Windows, install Npcap and run ShadowPulse as Administrator.

1. Install Npcap from https://nmap.org/npcap/.
2. During install, select **"WinPcap compatible mode"**.
3. Open a PowerShell prompt as Administrator.
4. In the backend folder, install dependencies and start the server:

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

5. Confirm the backend is running and the packet capture interface is selected.

6. If packet capture fails, verify Npcap is installed correctly and the selected adapter is active.

---

## Quick Start

### 1. Backend Setup

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The backend runs at **http://localhost:5000**.

#### Initialize the database

The database schema is created automatically when the backend starts. To add default configuration records and create runtime directories, call:

```bash
curl -X POST http://localhost:5000/init/setup
```

The backend starts all enabled detectors through one shared packet dispatcher; do not run detector modules as separate processes.

### 2. Frontend Setup (in a new terminal)

```bash
cd frontend
npm install
npm start
```

The frontend runs at the Vite URL shown by the command, normally **http://localhost:5173**.

### 3. Access the Dashboard

Open **http://localhost:5173** in your browser. The dashboard receives alert/device events over WebSocket and refreshes REST snapshots after reconnects.

---

## Configuration

### Backend - `shadowpulse.conf`

Configuration lives in `backend/shadowpulse.conf`. A default file is auto-generated if it does not exist. Key sections:

| Section | Description |
|---------|-------------|
| `[SYSTEM]` | Debug mode, log level, data retention, max log size, backups |
| `[NETWORK]` | Interface to monitor, scan interval, network range, timeouts |
| `[DETECTORS]` | Enable/disable each of the 7 detectors |
| `[ALERTS]` | Severity threshold, cooldown, and notification settings |
| `[DATABASE]` | SQLite path, pool size, timeout |
| `[BASELINES]` | Trusted DHCP/DNS servers and authorized access points |
| `[API]` | Host, port, secret key, CORS, rate limit |

The alert pipeline currently persists alerts and emits them to connected WebSocket clients.

### Frontend Configuration

The frontend reads these optional environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_API_BASE_URL` | `http://localhost:5000` | Backend API base URL |
| `VITE_WS_URL` | Derived from `VITE_API_BASE_URL` as `ws://.../ws` | Backend WebSocket URL |

When the API base URL uses HTTPS, the derived WebSocket URL uses secure WebSockets (`wss://`). Set `VITE_WS_URL` explicitly when the WebSocket endpoint is hosted separately.

---

## Detectors

| Detector | Attack Detected | Signals |
|----------|-----------------|---------|
| **ARP Spoofing** | ARP cache poisoning / MITM | MAC conflicts, gratuitous ARP, high request frequency |
| **DHCP Spoofing** | Rogue DHCP server / MITM | Rogue DHCP offers, gateway/DNS injection |
| **DNS Spoofing** | DNS response poisoning / hijacking | Unexpected DNS answers, rogue resolvers |
| **HTTP Injection** | Content injection in unencrypted pages | Injected scripts / fake login boxes in HTTP responses |
| **ICMP Redirect** | Traffic redirection / MITM | Malicious ICMP redirect messages |
| **Rogue Access Point** | Evil-twin / SSID impersonation | Unauthorized BSSIDs, impersonated SSIDs, open/hidden networks |
| **SSL Stripping** | HTTPS → HTTP downgrade | https-over-http, missing HSTS, TLS downgrade, redirect chains |

Each detector module can be individually enabled or disabled via the `[DETECTORS]` section of `shadowpulse.conf`.

### Network visibility limits

ShadowPulse can analyze only packets visible at its capture interface. On a typical switched Ethernet or Wi-Fi network, a computer does not see all unicast traffic exchanged by other devices. The rogue access point detector also depends on compatible 802.11 capture; monitor mode is disabled by default. HTTPS encryption limits inspection of page contents, so SSL-strip and HTTP-content checks rely on observable metadata and unencrypted traffic. Detection is limited by capture visibility and the evidence available in packets.

---


## Frontend Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Health status, live alerts, packet activity, critical count |
| **Live Monitoring** | Real-time feed of active events and packet rate |
| **Attack Analytics** | Charts, severity breakdown, heatmap, week-over-week trends |
| **Devices** | Discovered devices, vendors, trust/rogue status |
| **Rogue Access** | Authorized vs. nearby access points, evil-twin detection (requires compatible Wi-Fi capture for 802.11 visibility) |
| **SSL Strip Monitor** | HTTPS session status and downgrade warnings based on observable traffic |
| **Logs** | Search and filter alert history; network logs are available through the backend API |
| **Settings** | Monitoring controls and capture status; theme control is in the top bar |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| **CORS errors in the dashboard** | Ensure the frontend origin is allowed by the CORS middleware, then restart the backend. |
| **Database errors** | The schema is created when the backend starts. If default records or runtime directories are missing, call `POST /init/setup`. |
| **Dashboard shows offline** | Confirm backend is on `localhost:5000`, or set `VITE_API_BASE_URL` to the correct backend URL. |
| **Packet capture errors** | Verify the interface in `[NETWORK] interface` exists and that you have the required privileges / Npcap installed. |
---

## License

This project is provided for educational and security-research purposes. Use responsibly and only on networks you are authorized to monitor.
