# ShadowPulse - Real-Time MITM Attack Detection System

ShadowPulse is a network monitoring and MITM detection project. Its FastAPI backend captures packets through one shared Scapy `PacketDispatcher`, runs the enabled detectors, stores alerts and network observations in SQLite, and serves data to a React dashboard. The dashboard receives alert and device events over WebSocket and refreshes REST snapshots every 30 seconds. Detection is heuristic: an alert is evidence to investigate, not proof of a confirmed attack.

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
- **Detailed packet & alert logs**
- **Dark / light theme** toggle and real-time critical-alert toasts
- **Mock / live data modes** so the dashboard can run with or without the backend

---

## Architecture

| Layer | Technology | Port |
|-------|-----------|------|
| Backend API | Python · FastAPI · Uvicorn | `5000` |
| Database | SQLite | file `shadowpulse.db` |
| Packet Capture | Scapy | — |
| Frontend | React 18 · TypeScript · Vite · Tailwind CSS | `5173` by default |
| Charts | Recharts | — |
| Icons | lucide-react | — |

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│        React Frontend       │ REST + WebSocket │ FastAPI Backend       │
│  Dashboard · Live · Charts  │ ◀───────────────▶ │ /api/* + /ws           │
│  Rogue · SSL · Logs · etc.  │                  │ Shared Scapy capture  │
└─────────────────────────────┘        └──────────────┬───────────────┘
                                                      │
                                              ┌───────▼───────┐
                                              │ SQLite DB     │
                                              │ shadowpulse.db│
                                              └───────────────┘
```

## Project Structure

```text
ShadowPulse/
├── backend/
│   ├── app.py                  # FastAPI entry point and WebSocket
│   ├── shadowpulse.conf       # Backend configuration
│   ├── requirements.txt
│   ├── core/                  # Monitoring, packet dispatch, alerts, stats
│   ├── detectors/             # Seven packet detection modules
│   ├── routers/               # /api and /init endpoints
│   ├── routes/                # Dashboard, alert, device, log, network, report APIs
│   ├── models/                # Alert, device, log, and network dataclasses
│   ├── tests/                 # Backend regression tests
│   └── utils/                 # Config, database, logging, paths, scanner, parser
│       └── log_parser.py      # Parser utility; exported by utils/__init__.py
├── frontend/
│   ├── public/
│   └── src/
│       ├── components/
│       ├── context/
│       ├── lib/               # API client, types, mock data, formatting
│       └── pages/
├── README.md
└── .gitignore
```

The model dataclasses are present but are not currently used by backend routes or persistence, which work with SQLite rows and dictionaries. `utils/log_parser.py` provides packet/log parsing classes and is re-exported from `utils/__init__.py`; the active packet detection pipeline uses the detector modules and shared dispatcher instead. Keep these modules if you plan to use those interfaces; they are not required by the current monitoring flow.

---

## Prerequisites

- **Python 3.9+**
- **Node.js 18+** and **npm**
- A network interface to capture traffic (for live detection). On **Linux/macOS** packet capture typically requires root/admin privileges or `libpcap`; on **Windows**, use Npcap with the `scapy` backend.
- The dashboard can run **without** a capture interface using **mock data mode** (see [Frontend Configuration](#frontend-configuration)).

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

5. Confirm the backend is running and the packet capture interface is selected:

```powershell
curl.exe -sS http://127.0.0.1:5000/api/status
```

6. Trigger a live scan:

```powershell
curl.exe -sS -X POST http://127.0.0.1:5000/api/scan
```

7. If packet capture fails, verify Npcap is installed correctly and the selected adapter is active.

---

## Quick Start

### 1. Backend Setup

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The backend runs at **http://localhost:5000**.

> **Tip:** Create a virtual environment first to keep dependencies isolated:
>
> ```bash
> python -m venv venv
> # Windows:
> venv\Scripts\activate
> # macOS / Linux:
> source venv/bin/activate
> pip install -r requirements.txt
> ```

#### Initialize the database

The first time you run the backend (or to reset it), initialize the schema and default data:

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

Configuration lives in `backend/shadowpulse.conf` (INI format). A default file is auto-generated if it does not exist. Key sections:

| Section | Description |
|---------|-------------|
| `[SYSTEM]` | Debug mode, log level, data retention, max log size, backups |
| `[NETWORK]` | Interface to monitor, scan interval, network range, timeouts |
| `[DETECTORS]` | Enable/disable each of the 7 detectors |
| `[ALERTS]` | Severity threshold, email/SMS/webhook notifications, cooldown |
| `[DATABASE]` | SQLite path, pool size, timeout |
| `[API]` | Host, port, secret key, CORS, rate limit |

### Environment Variable Overrides

Backend settings can be overridden with environment variables:

| Variable | Maps to |
|----------|---------|
| `SHADOWPULSE_DEBUG` | `[SYSTEM] debug` |
| `SHADOWPULSE_INTERFACE` | `[NETWORK] interface` |
| `SHADOWPULSE_DB_PATH` | `[DATABASE] path` |
| `SHADOWPULSE_API_PORT` | `[API] port` |
| `SHADOWPULSE_SECRET_KEY` | `[API] secret_key` |

### Frontend Configuration

The frontend reads two environment variables (optionally set in `frontend/.env`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_API_BASE_URL` | `http://localhost:5000` | Backend API base URL |
| `VITE_WS_URL` | Derived from `VITE_API_BASE_URL` as `ws://.../ws` | Backend WebSocket URL |
| `VITE_USE_MOCK` | `false` | Set to `true` to use generated mock data instead of backend requests |

> **Example:** To force the frontend to use the live backend:
>
> ```bash
> VITE_USE_MOCK=false VITE_API_BASE_URL=http://localhost:5000 npm start
> ```

### Runtime data locations

The canonical database is `backend/shadowpulse.db`, and application logs are written under `backend/logs/`, regardless of the launch directory. Initialization creates the expected runtime directories under `backend/`. Report and log export endpoints currently write to an `exports/` directory relative to the backend process's working directory; the documented startup commands run the process from `backend/`. Existing root-level database files are separate and are not automatically migrated.

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

---

## API Reference

The backend exposes the dashboard snapshot and monitoring-control API under `/api/*`, plus feature endpoints under `/dashboard`, `/alerts`, `/devices`, `/logs`, `/network`, and `/reports`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/status` | Monitoring status and enabled detectors |
| `GET` | `/api/alerts` | Latest alerts (`?limit=N`) |
| `GET` | `/api/network` | Network info, gateway, connected devices |
| `GET` | `/api/statistics` | Aggregated stats for dashboard/analytics |
| `GET` | `/api/logs` | Recent log entries (`?limit=N`) |
| `GET` | `/api/rogue` | Rogue access point data |
| `GET` | `/api/ssl` | SSL strip session & warning data |
| `POST` | `/api/start` | Start monitoring |
| `POST` | `/api/stop` | Stop monitoring |
| `POST` | `/api/scan` | Trigger a network scan |
| `GET` | `/dashboard/stats` | System and security summary metrics |
| `GET` | `/alerts/` | Stored alerts; `/alerts/stats` returns alert summaries |
| `GET` | `/devices/` | Discovered devices |
| `GET` | `/logs/` | Stored network log entries |
| `GET` | `/network/topology` | Network topology data |
| `GET` | `/reports/security-summary` | Security summary report |
| `GET` | `/reports/threat-analysis` | Threat analysis report |
| `GET` | `/reports/compliance` | Compliance summary |
| `POST` | `/reports/export` | Export a report |
| `POST` | `/init/setup` | Initialize DB schema & default data |
| `GET` | `/init/status` | System initialization status |
| `GET` | `/init/health` | Backend health check |

The React client loads snapshots through FastAPI REST endpoints and receives alert/device events over `/ws`. A periodic REST refresh recovers state after reconnects and catches updates missed while disconnected. With `VITE_USE_MOCK=false`, backend request failures are surfaced to the dashboard; mock data is used only when mock mode is explicitly enabled.

---

## Frontend Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Health status, live alerts, packet activity, critical count |
| **Live Monitoring** | Real-time feed of active events and packet rate |
| **Attack Analytics** | Charts, severity breakdown, heatmap, week-over-week trends |
| **Devices** | Discovered devices, vendors, trust/rogue status |
| **Rogue Access** | Authorized vs. nearby access points, evil-twin detection |
| **SSL Strip Monitor** | HTTPS session status, downgrade warnings |
| **Logs** | Detailed packet and alert logs |
| **Settings** | Monitoring controls, theme toggle, configuration |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| **CORS errors in the dashboard** | Ensure the backend is running and CORS is enabled (`[API] cors_enabled = True`). Restart the backend after changes. |
| **Database errors** | Run the init endpoint: `curl -X POST http://localhost:5000/init/setup` |
| **No live data on the dashboard** | Confirm `VITE_USE_MOCK=false`, start the backend from `backend/`, and check capture privileges/Npcap and the configured interface. |
| **Dashboard shows offline** | Confirm backend is on `localhost:5000`, or set `VITE_API_BASE_URL` to the correct backend URL. |
| **Packet capture errors** | Verify the interface in `[NETWORK] interface` exists and that you have the required privileges / Npcap installed. |
| **Want to view the dashboard without the backend** | Set `VITE_USE_MOCK=true` in `frontend/.env` to use generated mock data. |

---

## License

This project is provided for educational and security-research purposes. Use responsibly and only on networks you are authorized to monitor.
