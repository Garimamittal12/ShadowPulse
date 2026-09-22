# ShadowPulse - Real-Time MITM Attack Detection System

ShadowPulse is a **real-time Man-in-the-Middle (MITM) attack detection system**. It continuously inspects network traffic for common MITM attack techniques-ARP/DNS/DHCP spoofing, SSL stripping, rogue access points, ICMP redirection, and HTTP injection-raises severity-ranked alerts, and visualizes the results in a live React dashboard.

It combines a **Python/Flask detection backend** with a **React + TypeScript + Tailwind dashboard** to give security analysts an at-a-glance view of their network's health, active threats, connected devices, and detailed attack analytics.

---

## Features

### Detection Engine (Backend)
- **Packet capture** using `scapy` with pluggable detector modules
- **7 built-in detectors** covering common Layer-2/3/4/7 attacks 
- **SQLite persistence** of alerts, devices, and detector status
- **Configurable monitoring** via `shadowpulse.conf` and environment variables
- **Multi-process detector runner** to monitor several attack vectors concurrently

### Dashboard (Frontend)
- **Live monitoring** with automatic polling every 3 seconds
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
| Backend API | Python · Flask · Flask-CORS | `5000` |
| Database | SQLite | file `shadowpulse.db` |
| Packet Capture | Scapy | — |
| Frontend | React 18 · TypeScript · Vite · Tailwind CSS | `3000` |
| Charts | Recharts | — |
| Icons | lucide-react | — |

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│        React Frontend       │  HTTP  │        Flask Backend         │
│  Dashboard · Live · Charts  │ ─────▶ │  /api/*  (REST endpoints)    │
│  Rogue · SSL · Logs · etc.  │        │  Detectors (scapy sniffers)  │
└─────────────────────────────┘        └──────────────┬───────────────┘
                                                      │
                                              ┌───────▼───────┐
                                              │ SQLite DB     │
                                              │ shadowpulse.db│
                                              └───────────────┘
```

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

#### (Optional) Seed sample data

To populate the dashboard with realistic sample alerts and devices:

```bash
cd backend
python seed_data.py
```

#### (Optional) Run the detectors

To start **all** packet-capture detectors as separate processes:

```bash
cd backend
python detector_running.py
```

### 2. Frontend Setup (in a new terminal)

```bash
cd frontend
npm install
npm start
```

The frontend runs at **http://localhost:3000**.

### 3. Access the Dashboard

Open **http://localhost:3000** in your browser. The dashboard polls the backend every 3 seconds and displays live threat status.

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
| `VITE_USE_MOCK` | `true` | When `false`, attempts to reach the real backend; falls back to mock data on failure |

> **Example:** To force the frontend to use the live backend:
>
> ```bash
> VITE_USE_MOCK=false VITE_API_BASE_URL=http://localhost:5000 npm start
> ```

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

The backend exposes a consolidated REST API under `/api/*`.

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
| `POST` | `/init/setup` | Initialize DB schema & default data |
| `GET` | `/init/status` | System initialization status |
| `GET` | `/init/health` | Backend health check |

Legacy blueprint routes are also mounted under `/legacy/*` for backward compatibility.

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
| **No data on the dashboard** | Start the detector runner (`python detector_running.py`) or seed sample data (`python seed_data.py`). |
| **Dashboard shows offline** | Confirm backend is on `localhost:5000`, or set `VITE_API_BASE_URL` to the correct backend URL. |
| **Packet capture errors** | Verify the interface in `[NETWORK] interface` exists and that you have the required privileges / Npcap installed. |
| **Want to run without a capture interface** | Use mock data mode (default `VITE_USE_MOCK=true`) so the dashboard works standalone. |

---

## License

This project is provided for educational and security-research purposes. Use responsibly and only on networks you are authorized to monitor.
