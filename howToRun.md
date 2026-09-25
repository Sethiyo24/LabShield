# How to Run LabShield

## Prerequisites
- Python 3.8+ installed.
- (Optional but recommended) **Run terminal as Administrator** for full network packet capture (DNS monitoring with Scapy).

---

## Step 1: Install Dependencies
Open a terminal in the `labshield` folder (or project root) and run:

```bash
cd labshield
pip install -r requirements.txt
```

---

## Step 2: Run the Monitoring Agent
The agent monitors student activity (active windows, clipboard, keystrokes, file changes, USB, DNS queries).

In Terminal 1 (Run as Administrator for full DNS packet capture):

```bash
cd labshield
python -m agent.main
```

---

## Step 3: Run the Dashboard (Flask Web UI)
The web dashboard provides the teacher view to monitor live activity, suspicion scores, rules, and AI verdicts.

In Terminal 2:

```bash
cd labshield
python -m dashboard.app
```

Then open your browser and go to:
👉 **[http://localhost:5000](http://localhost:5000)**

---

## Components Overview

| Component | Command | Purpose |
|---|---|---|
| **Monitoring Agent** | `python -m agent.main` | Runs background activity monitors |
| **Web Dashboard** | `python -m dashboard.app` | Teacher dashboard at `http://localhost:5000` |
