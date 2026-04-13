# FlamePerf Linux Analyzer

A web-based performance profiling tool for Linux systems. Collects `perf`, `iostat`, `iotop`, and `top` data on target machines, then visualizes the results as interactive flamegraphs, time-series charts, and sortable process tables.

Originally built for Nutanix CVM/FSVM diagnostics, but works on any Linux machine with `perf` installed.

## Features

- **Interactive Flamegraphs** — filter by process, PID, service, or search for specific functions. Toggle between active CPU and total (including idle) views.
- **Disk I/O (iostat)** — per-device time-series charts with per-second device table. Sortable columns, click-to-jump on chart.
- **Process I/O (iotop)** — per-second disk I/O by thread (TID) or process (PID). Toggle between Total and Actual throughput.
- **Top Processes** — time-series CPU usage chart (us/sy/wa/id) with per-second process table from `top -c`.
- **CPU Breakdown** — bar charts by thread or service, with active/total toggle.
- **Machine Detection** — auto-detects CVM, FSVM, PCVM, or generic Linux.
- **Admin Mode** — password-protected upload deletion and password management.
- **Dark/Light Theme** — toggle in the top nav.

## Architecture

```
perf-analyzer/
├── cvm-collector/
│   └── perf-collect.sh      # Data collection script (runs on target machines)
├── analyzer/
│   ├── app.py               # Flask web application
│   ├── parser.py            # Parses perf, iostat, iotop, top output
│   ├── diagnostics.py       # Automated finding detection
│   ├── models.py            # SQLite database layer
│   ├── Containerfile         # Container image definition
│   ├── requirements.txt     # Python dependencies (Flask, gunicorn)
│   ├── static/              # CSS, images
│   └── templates/           # Jinja2 HTML templates
├── deploy.sh                # One-command deployment script
└── README.md
```

## Prerequisites

**Analyzer server (where the web UI runs):**

- A Linux machine (RHEL/CentOS/Rocky 9 recommended) with:
  - `podman` (installed automatically by `deploy.sh` if missing)
  - Port 8080 available
  - A `/perfanal` directory (or change `REMOTE_BASE` in `deploy.sh`)
- Passwordless SSH access as root from your workstation to the server

**Target machines (where you collect profiling data):**

- `perf` installed (`linux-tools` / `perf` package)
- `sudo` access (perf record requires root)
- Optional: `iotop` for per-process disk I/O collection

## Deployment

### 1. Configure the target

Edit `deploy.sh` and set the `TARGET` variable to your server:

```bash
TARGET="root@your-server-ip"
```

### 2. Deploy

```bash
./deploy.sh
```

The script will:
1. Prompt you to set an **admin password** (used for the web UI admin mode)
2. Copy all files to the remote server
3. Build a container image with podman
4. Start the container on port 8080
5. Configure firewall rules and a systemd service for auto-restart

### 3. Access the UI

Open `http://your-server-ip:8080` in a browser.

## Collecting Data

### Download the collector

From the web UI, click **Download collector** in the top nav to get `perf-collect.sh`, or copy it directly from the server.

### Run on a target machine

```bash
# Basic usage (10s capture)
sudo bash perf-collect.sh --cluster-id my-cluster

# Custom duration and frequency
sudo bash perf-collect.sh --cluster-id my-cluster --duration 30 --frequency 199

# Custom output directory
sudo bash perf-collect.sh --cluster-id my-cluster --output-dir /tmp
```

This produces a `.tar.gz` bundle containing perf data, iostat, iotop, top snapshots, and system metadata.

### Upload for analysis

Upload the bundle through the web UI at `http://your-server-ip:8080/upload`, or use the dashboard's upload area.

## Management

```bash
# View container logs
ssh root@your-server podman logs -f perf-analyzer

# Restart the container
ssh root@your-server podman restart perf-analyzer

# Check systemd service status
ssh root@your-server systemctl status perf-analyzer

# Data is persisted in /perfanal/perf-analyzer/data/
```

## Admin Mode

Click the **Admin** button in the top nav and enter the password set during deployment. Admin mode enables:

- Deleting uploaded analyses
- Changing the admin password (persists across container restarts)

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

Created by Sergei Ivanov (sergei.ivanov@nutanix.com).
