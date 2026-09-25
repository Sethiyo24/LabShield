# LABSHIELD — Complete Build Prompt v2
### Practical Exam Anti-Cheating Surveillance System
**7th Semester Project | Single PC Version | Upgradeable to Distributed in 8th Sem**

---

## HOW TO USE THIS DOCUMENT WITH AN AI IDE

> This document is structured for use with **Cursor, Windsurf, or any AI-powered IDE**.
> Follow this exact workflow — do NOT skip ahead or paste multiple phases at once.

### AI IDE Workflow

```
STEP 1 — Start a NEW chat in your AI IDE
STEP 2 — Paste SECTION 9 (General Rules) FIRST — every single session
STEP 3 — Paste ONE Phase Prompt at a time
STEP 4 — Let the AI build and create ALL files before you review
STEP 5 — Run the Test Checklist before moving to the next phase
STEP 6 — If a test fails: paste ONLY the failed test back into the same chat
STEP 7 — When all tests pass: open a NEW chat and paste the next phase
```

### Why New Chat Per Phase?
AI IDEs work best with focused context. A single chat with too much history causes
the AI to lose track of earlier decisions, contradict itself, or hallucinate files
that don't exist. Each phase is a clean, scoped task.

### What to Do When the AI Goes Off-Track
```
If AI suggests React, FastAPI, PostgreSQL, Redis, Docker, or WebSocket:
  → Reply: "Stay in scope. This is a single PC 7th sem project. 
    Tech stack is fixed: Python agent + Flask + SQLite + Tailwind CDN."

If AI creates files in wrong folders:
  → Reply: "Recreate [filename] in the correct path: labshield/[correct/path]"

If AI skips a file or function:
  → Reply: "You skipped [function/file]. Build it now, following the spec exactly."

If AI shows code in chat without creating files:
  → Reply: "Create the actual file on disk. Do not just show code in chat."
```

---

# SECTION 1: PROJECT OVERVIEW

## 1.1 What is LabShield?

LabShield is a silent exam surveillance agent for college practical labs.
During a practical exam, students write code on a lab PC.
LabShield runs silently in the background, monitors everything the student
does, and gives the teacher a full evidence report with an AI verdict.

**The philosophy: Surveillance over blocking.**
We do not block any website or application. The student has full freedom.
But everything they do is being recorded with timestamps. They get caught
after, with undeniable evidence.

## 1.2 How It Works

```
BEFORE EXAM:
  Teacher runs LabShield → enters exam question + student name → clicks Start

DURING EXAM:
  Agent runs silently in background — student sees nothing
  Monitors: DNS queries (catches incognito too), active window titles,
            clipboard pastes, typing speed, files opened, USB drives
  Every event logged to SQLite: timestamp + event type + detail + HMAC signature

DURING OR AFTER EXAM:
  Teacher opens localhost:5000 in browser
  Dashboard auto-refreshes every 10 seconds — live view
  Full timeline of every event, score chart, DNS heatmap, velocity bars
  Teacher clicks "Ask AI" → Gemini Flash analyses log → verdict in <3 seconds
  Teacher exports full .txt report for records
```

## 1.3 System Architecture (Single PC)

```
┌──────────────────────────────────────────────────────────┐
│                      STUDENT PC                          │
│                                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │              LabShield Agent (silent)            │   │
│   │                                                  │   │
│   │  ┌────────────┐  ┌────────────┐  ┌───────────┐  │   │
│   │  │DNS Monitor │  │Window Mon. │  │Clipboard  │  │   │
│   │  │(Scapy)     │  │(pygetwindow│  │(pyperclip)│  │   │
│   │  └────────────┘  └────────────┘  └───────────┘  │   │
│   │  ┌────────────┐  ┌────────────┐  ┌───────────┐  │   │
│   │  │Keystroke   │  │File Mon.   │  │USB Monitor│  │   │
│   │  │(pynput)    │  │(watchdog)  │  │(psutil)   │  │   │
│   │  └────────────┘  └────────────┘  └───────────┘  │   │
│   │              ↓ logs every event                  │   │
│   └─────────────────────┬───────────────────────────┘   │
│                         │ thread-safe writes              │
│   ┌─────────────────────▼───────────────────────────┐   │
│   │        SQLite DB  (data/labshield.db)            │   │
│   │   activity_logs table | exam_session table       │   │
│   │   every row HMAC-signed for tamper detection     │   │
│   └─────────────────────┬───────────────────────────┘   │
│                         │                                 │
│   ┌─────────────────────▼───────────────────────────┐   │
│   │     Flask Dashboard  (localhost:5000)            │   │
│   │     Teacher browser → live stats + timeline      │   │
│   │     Rule engine → suspicion scoring              │   │
│   │     Gemini Flash → AI verdict                    │   │
│   └─────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

---

# SECTION 2: COMPLETE CHEAT DETECTION

| # | Cheat Method | Detection Method | Points |
|---|---|---|---|
| 1 | Google/Bing search | DNS query log | +15 |
| 2 | Search in incognito | DNS sniffing (Scapy bypasses browser privacy) | +15 |
| 3 | ChatGPT in browser | DNS flags chatgpt.com / chat.openai.com | +40 |
| 4 | Gemini in Chrome | DNS flags gemini.google.com + window title | +40 |
| 5 | Claude / Copilot | DNS flags claude.ai, copilot.microsoft.com | +40 |
| 6 | Perplexity / other AI | DNS flags domain | +35 |
| 7 | Online compiler (Replit) | DNS flags replit.com, programiz.com | +35 |
| 8 | Colab / JDoodle | DNS flags colab.research.google.com | +35 |
| 9 | Bitly shortened URL | DNS catches bit.ly + next query reveals destination | +20 |
| 10 | Pre-saved .py on PC | File open event flagged with timestamp | +25 |
| 11 | USB / Pen drive | Drive mount detected within 2 seconds | +25 |
| 12 | File from USB | File open from D:\ E:\ F:\ flagged | +25 |
| 13 | Gmail Drafts/Inbox | DNS flags mail.google.com + window title | +35 |
| 14 | Google Classroom | DNS flags classroom.google.com | +30 |
| 15 | Google Drive | DNS flags drive.google.com | +25 |
| 16 | OneDrive / Dropbox | DNS flags onedrive.live.com, dropbox.com | +25 |
| 17 | Copy-paste large code | Clipboard paste > 100 chars flagged | +30 |
| 18 | Paste into IDE | Keystroke velocity spike (paste = instant chars) | +30 |
| 19 | WhatsApp / Telegram Web | DNS + window title | +20 |
| 20 | GitHub / Stack Overflow | DNS flags domain | +20 |
| 21 | Pastebin / Hastebin | DNS flags domain | +30 |

## Suspicion Score Thresholds

```
Score   0 – 30   →  GREEN    — Looks clean
Score  31 – 80   →  YELLOW   — Suspicious, teacher should review
Score  81+       →  RED      — Strong evidence of cheating
```

---

# SECTION 3: TECH STACK (FIXED — DO NOT CHANGE)

## Agent (Monitoring)

| Purpose | Tool | Why |
|---|---|---|
| Core language | Python 3.11+ | Clean, explainable in viva |
| DNS sniffing | Scapy | Only way to catch incognito browsing |
| Window monitoring | pygetwindow | Lightweight, already tested |
| File monitoring | watchdog | Real-time file system events |
| Process & USB | psutil | Drive mount detection in 2 seconds |
| Clipboard | pyperclip | Paste event detection |
| Keystroke timing | pynput | Typing velocity only — NOT key content |
| Local database | SQLite (built-in) | No setup, file-based, zero config |
| Log signing | hmac + hashlib (built-in) | Tamper-proof evidence |

## Dashboard (Teacher View)

| Purpose | Tool | Why |
|---|---|---|
| Web server | Flask | Simple, no npm, runs with one command |
| Frontend | HTML + CSS (no framework) | Full control, fast, viva-friendly |
| Charts | Chart.js (CDN) | Easy timeline and score charts |
| AI verdict | Gemini Flash API | Free tier, fast, structured output |

## NOT included (8th semester):
- No PostgreSQL → SQLite is enough
- No Redis → no caching needed
- No WebSocket → polling every 10 seconds is fine
- No Docker → just run python main.py
- No React/TypeScript → plain HTML works perfectly

---

# SECTION 4: FOLDER STRUCTURE

```
labshield/
│
├── agent/
│   ├── main.py                     ← Entry point, starts all monitors
│   ├── config.py                   ← Settings (exam question, thresholds, API key)
│   ├── database.py                 ← SQLite read/write with thread lock
│   ├── security.py                 ← HMAC log signing and verification
│   └── monitors/
│       ├── __init__.py
│       ├── dns_monitor.py          ← Scapy DNS sniffing (catches incognito)
│       ├── window_monitor.py       ← Active window title every 1 second
│       ├── clipboard_monitor.py    ← Paste detection + size measurement
│       ├── keystroke_monitor.py    ← Typing velocity only (never key content)
│       ├── file_monitor.py         ← File open/modify events
│       └── usb_monitor.py          ← USB drive mount detection
│
├── dashboard/
│   ├── app.py                      ← Flask server (localhost:5000)
│   ├── rules.py                    ← Suspicion scoring rule engine
│   ├── ai_verdict.py               ← Gemini Flash integration
│   └── templates/
│       ├── index.html              ← Main dashboard (all stats + timeline)
│       └── about.html              ← About page (for viva prep)
│
├── data/
│   └── labshield.db                ← SQLite database (auto-created on first run)
│
├── logs/
│   └── errors.log                  ← Agent error log (never shown to student)
│
├── requirements.txt
├── README.md
├── run.bat                         ← Windows launcher (run as admin)
├── run.sh                          ← Linux/Mac launcher
├── start_dashboard.bat             ← Opens Flask + browser (Windows)
└── start_dashboard.sh              ← Opens Flask + browser (Linux/Mac)
```

---

# SECTION 5: DATABASE SCHEMA

```sql
-- Every monitored event, signed for tamper detection
CREATE TABLE IF NOT EXISTS activity_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,        -- ISO8601 e.g. 2025-06-15T10:14:23
    event_type   TEXT NOT NULL,        -- dns_query | window_change |
                                       -- clipboard_paste | keystroke_stats |
                                       -- file_open | usb_mount | usb_unmount
    detail       TEXT NOT NULL,        -- full human-readable detail
    flagged      INTEGER DEFAULT 0,    -- 1 if this event is suspicious
    points       INTEGER DEFAULT 0,    -- suspicion points for this event
    label        TEXT,                 -- "AI Tool" | "Large Paste" | etc.
    hmac_sig     TEXT                  -- HMAC-SHA256 of timestamp+type+detail
);

-- One row per exam session
CREATE TABLE IF NOT EXISTS exam_session (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    question     TEXT NOT NULL,        -- exam question entered by teacher
    started_at   TEXT NOT NULL,        -- ISO8601 timestamp
    ended_at     TEXT,                 -- NULL while exam is running
    student_name TEXT                  -- optional
);
```

---

# SECTION 6: DESIGN SYSTEM

> Apply this design system exactly in Phase 3. Every color and font decision
> is specified — do not deviate or "improve" it.

## Philosophy
Premium minimalist dark theme. Security operations centre aesthetic.
Statistic-heavy — every metric recorded is visible somewhere on the dashboard.
The goal: a teacher glancing at this screen should immediately understand the
risk level without reading a single word.

## Color Palette

```
Background (page):     #0d1117   — near-black, GitHub-dark inspired
Surface (cards):       #161b22   — slightly lighter, card backgrounds
Surface raised:        #1c2128   — hover states, nested elements
Border:                #21262d   — all borders, always 0.5px
Border strong:         #30363d   — emphasized borders, active states

Text primary:          #e6edf3   — main readable text
Text secondary:        #8b949e   — labels, sub-text
Text muted:            #484f58   — timestamps, hints, disabled

Green (clean/safe):    #3fb950   — score 0–30, clean events
Yellow (suspicious):   #d29922   — score 31–80, warning events
Red (danger):          #f85149   — score 81+, flagged events
Blue (accent):         #58a6ff   — links, buttons, focus
Purple (AI):           #bc8cff   — AI verdict card, AI-related UI
```

## Typography

```
UI font:      Inter (load from Google Fonts CDN)
Data font:    JetBrains Mono (load from Google Fonts CDN)

Sizes:
  Dashboard title:     13px, letter-spacing 0.1em, uppercase, #8b949e
  Stat card number:    28px, JetBrains Mono, font-weight 600
  Stat card label:     11px, uppercase, letter-spacing 0.08em, #8b949e
  Body text:           13px, Inter, #e6edf3
  Timestamps:          12px, JetBrains Mono, #484f58
  Event detail:        12px, Inter, #8b949e
  Points badge:        11px, JetBrains Mono, font-weight 600
```

## Component Rules

```
Cards:
  background: #161b22
  border: 0.5px solid #21262d
  border-radius: 10px
  padding: 16px

Header bar:
  background: #0d1117
  border-bottom: 0.5px solid #21262d
  height: 48px
  position: sticky, top: 0
  z-index: 100

Buttons:
  Default:  border: 0.5px solid #30363d, bg transparent, text #8b949e
  Primary:  border: 0.5px solid #58a6ff, bg transparent, text #58a6ff
  Danger:   border: 0.5px solid #f85149, bg rgba(248,81,73,0.1), text #f85149
  No rounded corners beyond 6px. No shadows. No gradients.

Event pills / badges:
  Red:      bg rgba(248,81,73,0.15), text #f85149, border rgba(248,81,73,0.3)
  Yellow:   bg rgba(210,153,34,0.15), text #d29922, border rgba(210,153,34,0.3)
  Green:    bg rgba(63,185,80,0.15), text #3fb950, border rgba(63,185,80,0.3)
  Blue:     bg rgba(88,166,255,0.15), text #58a6ff, border rgba(88,166,255,0.3)
  Purple:   bg rgba(188,140,255,0.15), text #bc8cff, border rgba(188,140,255,0.3)
  Padding: 2px 8px, border-radius: 4px, font-size: 11px, monospace

Timeline left border:
  Flagged (red):   border-left: 2px solid #f85149
  Warning (yellow): border-left: 2px solid #d29922
  Clean:           border-left: 2px solid #21262d

No gradients. No drop shadows. No glow effects. No background images.
Flat surfaces only. The data is the decoration.
```

## Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  HEADER BAR (sticky, 48px)                                      │
│  [●LABSHIELD]  [exam question truncated]  [LIVE●][timer][AI][X] │
└─────────────────────────────────────────────────────────────────┘

┌──────────┬──────────┬──────────┬──────────┬──────────┐
│ SCORE    │ EVENTS   │ FLAGGED  │KEYSTROKES│ PASTES   │  ← STAT ROW
│ 82       │ 147      │  23      │  1,204   │   4      │    5 equal cards
│ HIGH RISK│since9:08 │ of 147   │avg 2.1/s │ 2 flagged│
└──────────┴──────────┴──────────┴──────────┴──────────┘

┌────────────────────────┬──────────────────────────────┐
│ SCORE OVER TIME        │ BREAKDOWN                    │  ← MIDDLE LEFT + RIGHT
│ Chart.js line chart    │ Rule-by-rule points bars     │
├────────────────────────┤                              │
│ KEYSTROKE VELOCITY     │                              │
│ HTML manual bars       ├──────────────────────────────┤
│                        │ AI VERDICT                   │
└────────────────────────┴──────────────────────────────┘

┌──────────────────────────────┬─────────────────────────┐
│ ACTIVITY TIMELINE            │ TOP DNS QUERIES         │  ← BOTTOM ROW
│ All events, newest first     │ + WINDOW FOCUS TIME     │
│ scrollable, 320px max        │                         │
│                              │ [Export][DNS][Clear]    │
└──────────────────────────────┴─────────────────────────┘
```

## What Makes It "Statistic Heavy"

Every single metric that is recorded must be visible somewhere:
- Total suspicion score (giant number, color-coded)
- Score over time (line chart — shows when cheating happened)
- Event count (total, flagged, by type)
- Keystroke velocity per window (every burst is a bar)
- Clipboard: count, flagged count, largest paste size
- DNS: every domain queried, how many times, color-coded risk
- Window focus: every app, total time spent in it
- USB: mount/unmount timestamps
- File access: every flagged file path
- HMAC status: whether log integrity is verified

The teacher should be able to reconstruct the entire exam session from this dashboard alone.

---

# SECTION 7: PHASE-BY-PHASE BUILD GUIDE

---

## PHASE 1 — Silent Monitoring Agent

**Goal:** The agent runs, all 6 monitors log to SQLite, HMAC signing works.
**You know it's done when:** You open SQLite browser and see real events flowing in.

---

### PASTE THIS INTO YOUR AI IDE FOR PHASE 1

```
Build the silent monitoring agent for LabShield — a 7th semester college
project that monitors a student PC during practical exams.

WHAT TO BUILD:
A Python agent with 6 background monitors that log events to SQLite.
No GUI. Student sees nothing. Runs with: python -m agent.main

PROJECT RULES (follow exactly — do not deviate):
- Tech: Python 3.11+, Scapy, pygetwindow, watchdog, psutil, pyperclip, pynput, SQLite
- NO React, NO FastAPI, NO Redis, NO Docker, NO WebSocket
- Create ALL files on disk — never just show code in chat
- Every function must have a docstring
- Every non-obvious line must have an inline comment
- All exceptions caught and written to logs/errors.log with timestamp
- Agent must never fully crash — if one monitor fails, others keep running
- All monitor threads must be daemon threads

FILES TO CREATE (create each one):

labshield/agent/config.py
  EXAM_QUESTION = ""              # teacher fills before exam
  STUDENT_NAME = ""               # optional
  DB_PATH = "data/labshield.db"
  LOG_PATH = "logs/errors.log"
  HMAC_SECRET = "labshield-secret-change-this"
  CLIPBOARD_FLAG_THRESHOLD = 100  # chars — paste above this is suspicious
  KEYSTROKE_WINDOW = 5            # seconds per velocity measurement
  KEYSTROKE_VELOCITY_THRESHOLD = 20  # chars/sec above this = suspicious
  GEMINI_API_KEY = ""             # get from https://aistudio.google.com/app/apikey

labshield/agent/database.py
  Create SQLite DB and both tables on first run (CREATE TABLE IF NOT EXISTS)
  Thread-safe writes: use threading.Lock() for all writes
  Functions:
    init_db()                     → creates tables if not exist
    insert_event(timestamp, event_type, detail, flagged, points, label, hmac_sig)
    get_all_events()              → list of all rows as dicts
    get_flagged_events()          → list of flagged rows only
    get_total_score()             → sum of all points
    create_session(question, student_name) → inserts exam_session row
    end_session()                 → updates ended_at on latest session
    get_current_session()         → returns latest session row as dict

labshield/agent/security.py
  sign_row(row_dict) → returns HMAC-SHA256 hex string
    Signs concatenation of: row_dict['timestamp'] + row_dict['event_type'] + row_dict['detail']
    Key from config.HMAC_SECRET
  verify_row(row_dict, signature) → returns True/False
    Recomputes HMAC and compares with constant-time hmac.compare_digest()

labshield/agent/monitors/dns_monitor.py
  Use Scapy to sniff DNS query packets.
  Filter: only DNS packets with DNSQR (query record).
  Extract: queried domain, strip trailing dot, convert to lowercase.
  Skip: domains ending in .local, .arpa, .internal (system noise).
  Log: event_type="dns_query", detail=domain, flagged=0, points=0 initially.
       (Rule engine in Phase 2 will add points later.)
  Must handle ImportError from Scapy with clear message:
    "DNS monitoring requires Scapy. Run as Administrator/root."
  Run as daemon thread.

labshield/agent/monitors/window_monitor.py
  Poll active window title every 1 second using pygetwindow.getActiveWindowTitle()
  Only log when title CHANGES (avoid duplicate entries)
  Extract:
    - If browser: extract page title (before " - Chrome" or "- Firefox")
    - If IDE (VS Code, PyCharm, Sublime): extract filename from title
    - Otherwise: use full window title
  Log: event_type="window_change", detail=extracted_title
  Special flag: if title contains any of:
    "Gmail", "Inbox", "Drafts", "Google Classroom", "Google Drive"
    → flagged=1, points=35, label="Suspicious App"
  Run as daemon thread.

labshield/agent/monitors/clipboard_monitor.py
  Poll clipboard every 0.5 seconds using pyperclip.paste()
  Track previous content. Only log when content changes AND content is non-empty.
  Log: event_type="clipboard_paste"
       detail = f"Length: {len(content)} chars | Preview: {content[:100].strip()}"
  If len(content) > config.CLIPBOARD_FLAG_THRESHOLD:
    flagged=1, points=30, label="Large Paste"
  Handle pyperclip exceptions (Linux may not have xclip installed).
  Run as daemon thread.

labshield/agent/monitors/keystroke_monitor.py
  Use pynput.keyboard.Listener to count keypresses.
  IMPORTANT: Do NOT log actual key characters. Only total count per window.
  Every config.KEYSTROKE_WINDOW seconds: calculate rate = keypress_count / window_seconds
  Log: event_type="keystroke_stats"
       detail = f"Rate: {rate:.1f} keys/sec over {window}s window | Total keys: {total}"
  If rate > config.KEYSTROKE_VELOCITY_THRESHOLD:
    flagged=1, points=30, label="Paste Velocity"
  Reset counter after each window.
  Run as daemon thread.

labshield/agent/monitors/file_monitor.py
  Use watchdog Observer to monitor:
    - os.path.expanduser("~/Desktop")
    - os.path.expanduser("~/Documents")
    - os.path.expanduser("~")
    - D:\, E:\, F:\, G:\ (USB paths — watch if they exist)
  On FileOpenedEvent or FileModifiedEvent:
    Log: event_type="file_open", detail=event.src_path
    If extension in [.py, .java, .c, .cpp, .js, .txt, .docx]:
      flagged=1, points=25, label="Code File Accessed"
    If path starts with D:\ or E:\ or F:\ or G:\:
      flagged=1, points=25, label="USB File Access"
  Skip log files and temp files (ending in .log, .tmp, ~).
  Run as daemon thread.

labshield/agent/monitors/usb_monitor.py
  Use psutil.disk_partitions(all=True) polling every 2 seconds.
  Track set of known partitions at startup.
  When new REMOVABLE partition appears (opts contains 'removable' or partition type is not fixed):
    Log: event_type="usb_mount"
         detail = f"Drive {device} mounted at {mountpoint} ({fstype})"
         flagged=1, points=25, label="USB Detected"
  When known partition disappears:
    Log: event_type="usb_unmount"
         detail = f"Drive {device} removed at {datetime.now()}"
  Run as daemon thread.

labshield/agent/main.py
  Import all 6 monitors
  Call database.init_db()
  Call database.create_session(config.EXAM_QUESTION, config.STUDENT_NAME)
  Start each monitor in its own daemon thread
  Print clear startup banner to console:
    "════════════════════════════════════"
    "  LabShield v1.0 — Monitoring Active"
    "════════════════════════════════════"
    "  Student: [name or 'unnamed']"
    "  Database: [DB_PATH]"
    "  DNS Monitor: [Active/Requires Admin]"
    "  Press Ctrl+C to stop and end session"
  Block with: while True: time.sleep(1)
  On KeyboardInterrupt:
    database.end_session()
    Print session summary: total events logged, total score
    Exit cleanly

labshield/requirements.txt:
scapy>=2.5.0
pygetwindow>=0.0.9
watchdog>=3.0.0
psutil>=5.9.0
pyperclip>=1.8.2
pynput>=1.7.6
flask>=3.0.0
requests>=2.31.0

labshield/data/.gitkeep
labshield/logs/.gitkeep
labshield/agent/__init__.py     (empty)
labshield/agent/monitors/__init__.py  (empty)

ERROR HANDLING STANDARD (apply to every monitor):
  Every monitor's main loop must be wrapped in try/except Exception as e:
    error_msg = f"{datetime.now().isoformat()} | {monitor_name} | ERROR: {str(e)}\n"
    Write to config.LOG_PATH
    Sleep 5 seconds and continue (do not exit thread)
```

---

### Phase 1 Test Checklist

Before moving to Phase 2, every item must pass:

- [ ] `cd labshield && python -m agent.main` starts without import errors
- [ ] Console shows the startup banner with all 6 monitors listed
- [ ] Open Chrome (any mode), visit any website → dns_query row appears in SQLite within 3 seconds
- [ ] Open Chrome incognito, visit google.com → dns_query STILL appears (incognito doesn't hide DNS)
- [ ] Copy 200+ characters of text → clipboard_paste row with flagged=1
- [ ] Open a .py file from Desktop → file_open row with flagged=1 appears
- [ ] Plug in USB drive → usb_mount event appears within 5 seconds
- [ ] Open SQLite browser → every row has hmac_sig column filled (not null, not empty)
- [ ] Open `logs/errors.log` → file exists, should be empty or only minor warnings
- [ ] Force one monitor to crash (temporarily raise Exception in it) → other monitors keep logging

---

## PHASE 2 — Rule Engine + Suspicion Scoring

**Goal:** The rule engine reads events from SQLite and calculates the total suspicion score.
**You know it's done when:** `run_rules_on_all_events()` returns a number that matches the detected events.

---

### PASTE THIS INTO YOUR AI IDE FOR PHASE 2

```
Add the suspicion scoring rule engine to LabShield.

PROJECT CONTEXT:
LabShield is a 7th semester single-PC exam surveillance system.
Python agent + Flask + SQLite only. Tech stack is fixed.
Create all files on disk. Every function must have a docstring.

BUILD labshield/dashboard/rules.py

SUSPICIOUS_DOMAINS (dictionary mapping domain → (points, label)):
  # AI Tools — highest points, clearest evidence of cheating
  "chatgpt.com": (40, "AI Tool"),
  "chat.openai.com": (40, "AI Tool"),
  "gemini.google.com": (40, "AI Tool"),
  "claude.ai": (40, "AI Tool"),
  "copilot.microsoft.com": (40, "AI Tool"),
  "perplexity.ai": (35, "AI Tool"),
  "blackboxai.com": (35, "AI Tool"),
  "you.com": (35, "AI Tool"),

  # Online Compilers
  "programiz.com": (35, "Online Compiler"),
  "replit.com": (35, "Online Compiler"),
  "onecompiler.com": (35, "Online Compiler"),
  "colab.research.google.com": (35, "Online Compiler"),
  "jdoodle.com": (35, "Online Compiler"),
  "ideone.com": (35, "Online Compiler"),
  "compiler.io": (35, "Online Compiler"),
  "onlinegdb.com": (35, "Online Compiler"),

  # Email and cloud storage
  "mail.google.com": (35, "Gmail Access"),
  "classroom.google.com": (30, "Google Classroom"),
  "drive.google.com": (25, "Cloud Storage"),
  "docs.google.com": (25, "Cloud Storage"),
  "onedrive.live.com": (25, "Cloud Storage"),
  "dropbox.com": (25, "Cloud Storage"),

  # Code sharing and references
  "github.com": (20, "Code Repository"),
  "stackoverflow.com": (20, "Code Reference"),
  "pastebin.com": (30, "Code Sharing"),
  "hastebin.com": (30, "Code Sharing"),

  # Search engines
  "google.com": (15, "Search Engine"),
  "bing.com": (15, "Search Engine"),
  "duckduckgo.com": (15, "Search Engine"),

  # Messaging
  "web.whatsapp.com": (20, "Messaging"),
  "web.telegram.org": (20, "Messaging"),
  "discord.com": (20, "Messaging"),

  # URL shorteners (used to hide destinations)
  "bit.ly": (20, "URL Shortener"),
  "tinyurl.com": (20, "URL Shortener"),
  "t.co": (20, "URL Shortener"),
  "rb.gy": (20, "URL Shortener"),

SCORE THRESHOLDS (constants):
  SCORE_GREEN_MAX = 30
  SCORE_YELLOW_MAX = 80
  # 81+ is RED

FUNCTIONS:

score_dns_event(domain: str) → tuple[int, str | None]
  Checks if domain matches any key in SUSPICIOUS_DOMAINS.
  First: exact match (domain == key).
  Then: suffix match (domain ends with "." + key) for subdomains.
  Returns (points, label) if matched, else (0, None).

score_window_event(window_title: str) → tuple[int, str | None]
  Checks window title for keywords:
    "Gmail" or "Inbox" or "Drafts" or "Sent" → (35, "Gmail Access")
    "Google Classroom" or "classroom.google" → (30, "Google Classroom")
    "Google Drive" or "drive.google" → (25, "Cloud Storage")
  Case-insensitive matching.
  Returns (points, label) or (0, None).

get_score_color(total_score: int) → str
  Returns "green" | "yellow" | "red" based on thresholds.

get_score_label(total_score: int) → str
  Returns "Clean" | "Suspicious" | "High Risk"

run_rules_on_all_events() → int
  Reads ALL events from DB.
  For each event with event_type == "dns_query":
    Call score_dns_event(event['detail'])
    If points > 0 and event['points'] == 0:  # don't re-score already-scored events
      Update that row in DB: SET flagged=1, points=points, label=label
  For each event with event_type == "window_change":
    Call score_window_event(event['detail'])
    If points > 0 and event['points'] == 0:
      Update DB row
  Return: sum of all points across all events in DB

Also add to database.py:
  update_event_score(event_id, points, label)
    UPDATE activity_logs SET flagged=1, points=?, label=? WHERE id=?

CONSTRAINTS:
  Pure Python, zero external libraries.
  All functions documented with docstrings.
  Adding a new domain to detect = adding one line to SUSPICIOUS_DOMAINS dict.
```

---

### Phase 2 Test Checklist

- [ ] `from dashboard.rules import run_rules_on_all_events, score_dns_event, get_score_color` imports without error
- [ ] `score_dns_event("chatgpt.com")` returns `(40, "AI Tool")`
- [ ] `score_dns_event("subdomain.replit.com")` returns `(35, "Online Compiler")` (subdomain matching)
- [ ] `score_dns_event("youtube.com")` returns `(0, None)` (not in list)
- [ ] `get_score_color(25)` → `"green"`, `get_score_color(55)` → `"yellow"`, `get_score_color(95)` → `"red"`
- [ ] Run `run_rules_on_all_events()` after Phase 1 data → DNS events get points in SQLite
- [ ] Open SQLite browser, confirm chatgpt.com row now has points=40, label="AI Tool", flagged=1

---

## PHASE 3 — Teacher Dashboard

**Goal:** A premium dark statistic-heavy Flask dashboard. Every metric visible.
**You know it's done when:** You can sit a teacher in front of it and they immediately understand everything that happened during the exam.

---

### PASTE THIS INTO YOUR AI IDE FOR PHASE 3

```
Build the teacher dashboard for LabShield.
This is the most important user-facing part of the project.

PROJECT CONTEXT:
LabShield is a 7th semester single-PC exam surveillance system.
Flask + plain HTML/CSS + Chart.js CDN only. No Tailwind. No React.
Dashboard runs at localhost:5000.
Teacher opens it during or after the exam to see all activity.

DESIGN PHILOSOPHY (read this before writing a single line of HTML):
Premium minimalist dark theme. Security operations centre aesthetic.
Every number recorded must be visible somewhere on the dashboard.
The teacher should be able to reconstruct the entire exam session from this
screen alone. Statistic-heavy: more data, less decoration.
The data is the design. Clean, flat, dark surfaces. Numbers in large mono font.

DESIGN SYSTEM (apply EXACTLY — no deviations):
  --bg:            #0d1117
  --surface:       #161b22
  --surface-hi:    #1c2128
  --border:        #21262d
  --border-hi:     #30363d
  --text:          #e6edf3
  --text-sub:      #8b949e
  --text-muted:    #484f58
  --green:         #3fb950
  --yellow:        #d29922
  --red:           #f85149
  --blue:          #58a6ff
  --purple:        #bc8cff

  Fonts (load both from Google Fonts CDN):
    Inter for all UI text
    JetBrains Mono for all numbers, timestamps, domain names, code
  
  Card: background var(--surface), border 0.5px solid var(--border), border-radius 10px
  No gradients. No shadows. No glow. Flat surfaces only.

BUILD dashboard/app.py (Flask server):

ROUTES:
  GET  /          → render index.html
  GET  /about     → render about.html
  GET  /api/score → JSON with ALL of:
    {
      total_score, score_color, score_label,
      event_count, flagged_count,
      keystroke_count, avg_keystroke_rate,
      clipboard_count, clipboard_flagged_count, largest_paste_chars,
      dns_count, usb_events,
      top_domains: [{domain, count, points, label, flagged}],  ← top 10 by count
      window_focus: [{app, seconds, flagged}],                 ← all apps + time
      score_history: [{time, cumulative_score}],               ← for line chart
      session: {question, student_name, started_at, ended_at, duration_minutes},
      keystroke_history: [{timestamp, rate, flagged}]          ← last 8 windows
    }
  GET  /api/events → JSON list of all events, newest first:
    [{id, timestamp, event_type, detail, flagged, points, label}]
  POST /api/start  → body: {question, student_name}
                     creates session, returns {success: true}
  POST /api/end    → calls database.end_session(), returns {success: true}
  POST /api/verdict → calls ai_verdict.get_ai_verdict(), returns verdict JSON
  GET  /export    → returns downloadable .txt file (Content-Disposition: attachment)

Before each /api/score and /api/events call: run rules.run_rules_on_all_events()
This ensures scoring is always fresh.

Score history calculation:
  Read all events ordered by timestamp.
  Walk through events chronologically, accumulating points.
  Every 60 seconds of exam time, emit a {time, cumulative_score} datapoint.
  This gives the line chart its data.

Window focus time calculation:
  Read all window_change events ordered by timestamp.
  For each consecutive pair: duration = next_timestamp - this_timestamp
  Accumulate duration per app name.
  Group Chrome/Firefox entries by whether they were flagged (visited suspicious sites).

BUILD dashboard/templates/index.html (ALL CSS AND JS INLINE):

HEADER (sticky, 48px, z-index 100):
  Left:   Red filled circle 8px + "LABSHIELD" (12px, letter-spacing 0.12em, --text-sub)
          separator · [exam question truncated to 60 chars, --text-muted, 12px]
  Right:  Green dot + "LIVE" (11px, --green) if session active, "ENDED" (--red) if not
          | elapsed timer (JetBrains Mono, 13px, --text) updating every second
          | [Ask AI] button (--blue outline)
          | [End Exam] button (--red tint, shows confirm dialog)

STAT ROW (5 cards, CSS grid, equal columns, gap 10px, margin-bottom 12px):
  Card 1 — Suspicion Score:
    Label: "SUSPICION SCORE" (11px uppercase mono muted)
    Number: total_score (28px, JetBrains Mono, color: green/yellow/red based on score)
    Sub: score_label (11px, same color, e.g. "HIGH RISK")
    Bottom strip: 3px solid bar, full width, color green/yellow/red (like a progress bar at bottom of card)

  Card 2 — Events Logged:
    Label: "EVENTS LOGGED"
    Number: event_count
    Sub: "since " + started_at formatted as HH:MM

  Card 3 — Flagged Events:
    Label: "FLAGGED"
    Number: flagged_count (color --red if > 0, else --text)
    Sub: "of " + event_count + " total"

  Card 4 — Keystrokes:
    Label: "KEYSTROKES"
    Number: keystroke_count (mono)
    Sub: "avg " + avg_keystroke_rate + "/sec"

  Card 5 — Clipboard Pastes:
    Label: "CLIPBOARD PASTES"
    Number: clipboard_count
    Sub: clipboard_flagged_count + " large (>" + THRESHOLD + " chars)"

MIDDLE ROW (CSS grid: left 60%, right 40%, gap 10px):

  LEFT COLUMN (two cards stacked, gap 10px):

  Card A — "Score over time" (Chart.js line chart):
    Title: "SUSPICION SCORE OVER TIME" (section label style)
    Chart height: 160px, responsive: true, maintainAspectRatio: false
    X axis: time labels (JetBrains Mono, 10px, --text-muted)
    Y axis: cumulative score, min 0 (--text-muted ticks)
    Dataset: line color #f85149, lineWidth 2, fill true with rgba(248,81,73,0.08)
    Grid lines: #21262d
    No legend. No data points (tension: 0.3)
    Canvas can't use CSS vars — use hex directly.
    Update via JavaScript fetch every 10 seconds.

  Card B — "Keystroke velocity":
    Title: "KEYSTROKE VELOCITY"
    Sub-title: "Spike = code pasted instead of typed"
    Show last 8 keystroke_stats events as horizontal bar rows.
    Each row:
      timestamp (10px, JetBrains Mono, --text-muted, 60px fixed)
      bar (flex-grow, height 20px, border-radius 3px):
        Fill: --green if rate < threshold, --red if >= threshold
        Width: proportional to rate (max bar = highest rate seen)
      rate value (10px, JetBrains Mono, right-aligned, color matches bar)
    If ANY bar is red: show warning below:
      "⚠ Paste velocity at [time] — [rate] keys/sec exceeds human typing"
      (12px, --yellow, margin-top 8px)

  RIGHT COLUMN (two cards stacked, gap 10px):

  Card C — "Score breakdown":
    Title: "SCORE BREAKDOWN"
    For each unique label that contributed points, show one row:
      label text (13px, --text-sub)
      horizontal bar (height 6px, --red fill, width proportional to points)
      "+XX pts" (11px, JetBrains Mono, --red)
    Total line at bottom: border-top 0.5px --border, margin-top 8px
      "TOTAL" (--text-muted) ... score (20px, JetBrains Mono, score color)
    If score is 0: "No suspicious activity detected" in --green center-aligned

  Card D — "AI Verdict":
    Title: "AI VERDICT"
    Before AI click: placeholder text centered:
      "Click 'Ask AI' in the header to analyse this session"
      (13px, --text-muted, italic)
    After verdict loads (via JavaScript, no page navigation):
      Verdict badge: full-width, 40px height, center
        "LIKELY CHEATED" → background rgba(248,81,73,0.15), color --red, border --red
        "POSSIBLY CHEATED" → yellow tint
        "LIKELY CLEAN" → green tint
      Confidence + model: "Confidence: HIGH · Gemini Flash" (11px, --text-muted)
      Reason: 13px, --text-sub, margin-top 8px
      Key evidence list: 3 items, each with red dot ● prefix, 12px, --text-sub
      Two buttons: [Confirm Cheat] (--green outline) | [Dismiss] (--border outline)

BOTTOM ROW (CSS grid: left 55%, right 45%, gap 10px):

  Card E — "Activity Timeline":
    Title: "ACTIVITY TIMELINE" + count badge (e.g. "147 events")
    Controls: [Flagged only] toggle button | [Newest first] (default)
    Scrollable div, max-height 320px, overflow-y auto
    Each event row (padding 6px 0, border-bottom 0.5px --border):
      Left border 2px:
        Flagged red event: #f85149
        Flagged yellow event: #d29922
        Clean event: #21262d
      Timestamp: 10px JetBrains Mono --text-muted, 65px fixed, flex-shrink 0
      Event type icon (emoji, 14px):
        dns_query → 🌐
        window_change → 🪟
        clipboard_paste → 📋
        file_open → 📁
        usb_mount / usb_unmount → 💾
        keystroke_stats → ⌨
      Detail text: 12px Inter --text-sub, flex-grow, ellipsis overflow
      If flagged: right-side badges:
        Points pill: "+40" (11px mono, red pill)
        Label pill: "AI Tool" (11px, red pill)
    Show all events (no "show 30" limit — the scroll handles it)
    JavaScript: scroll to bottom of div on first load (newest event visible)

  Card F — "Top DNS Queries" + "Window Focus Time":
    Section 1: "TOP DNS QUERIES"
    Show top 10 domains by query count:
      Each row:
        domain (12px JetBrains Mono, color: --red if flagged, --green if clean, --text-muted if CDN noise)
        horizontal mini-bar (height 4px, proportional to count)
        count × (10px mono, --text-muted)
        label badge if flagged ("AI Tool", "Code Reference", etc.)
      Bar colors: red for flagged domains, #21262d for clean
    
    Divider line (0.5px --border, margin 12px 0)
    
    Section 2: "WINDOW FOCUS TIME"
    Show all apps with time spent:
      Each row:
        app name (12px Inter, truncated at 120px)
        horizontal bar proportional to time (height 4px)
        duration (10px JetBrains Mono, --text-muted, format: "24m 32s")
      Bar colors: --green for IDE apps (VS Code, PyCharm, IDLE)
                  --red for browsers with flagged activity
                  --blue for everything else

    Bottom action strip (3 buttons, flex, gap 8px, margin-top 12px):
      [📥 Export Report] (--blue outline, click → GET /export)
      [🌐 DNS Log]       (--border, click → filters timeline to dns_query only)
      [🗑 Clear Session]  (--red tint, click → confirm dialog → POST /api/end)

START EXAM MODAL (shown when no active session exists):
  Full-screen overlay: position fixed, top 0, left 0, width 100%, height 100%
  Background: rgba(13,17,23,0.95)
  Centered card (max-width 440px, padding 32px, --surface, 10px radius):
    Top: ● LABSHIELD (centered, red dot + title same as header)
    H2: "Start Exam Session" (20px, --text, margin-bottom 24px, center)
    Label + Textarea: "Exam Question" (required)
      Textarea: 4 rows, resize: vertical, --surface-hi bg, --border border, --text color
    Label + Input: "Student Name" (optional)
      Input: text, --surface-hi bg, --border border, --text color
    Button: "Start Monitoring" (full width, 40px, --blue bg rgba(88,166,255,0.2), --blue border, --blue text)
    Error text area (hidden by default, shown in --red if POST /api/start fails)
  Submits via JavaScript fetch POST /api/start, hides modal on success

JAVASCRIPT (all inline in <script> at bottom of body):

  Auto-refresh:
    setInterval(refreshAll, 10000)  ← every 10 seconds
    refreshAll() calls refreshScore() then refreshEvents()

  refreshScore():
    fetch('/api/score') → update:
      All 5 stat cards (score number, colors, sub-labels)
      Score chart (destroy and recreate with new data)
      Keystroke velocity bars
      Score breakdown bars
      DNS top domains list
      Window focus time list

  refreshEvents():
    fetch('/api/events') → rebuild activity timeline
    Apply current filter (all or flagged only)

  AI Verdict:
    [Ask AI] button → show loading spinner in Card D
    POST /api/verdict → on success, render verdict in Card D
    No page navigation needed

  Exam timer:
    On page load: read session.started_at from /api/score
    setInterval every 1 second: calculate elapsed time, update header timer
    Format: "1h 23m 45s" or "45m 12s" or "23s"

  Modal:
    On page load: fetch /api/score → if session is null: show modal
    On "Start Monitoring" click: POST /api/start → hide modal, start timer

ABOUT PAGE (dashboard/templates/about.html):
  Same dark design system.
  Header bar with back link.
  Content sections:
    1. "About LabShield" — 2 paragraphs: what it is, who it's for
    2. "Detection Methods" — one card per monitor type, explaining what it detects and how
    3. "Tech Stack" — table of each tool with a one-line explanation
    4. "Why Each Method Works" — explains DNS sniffing, HMAC signing, keystroke velocity
    5. "Future Scope" — describes the 8th semester distributed version
  This page exists for viva preparation — the student should be able to point to it
  and answer "how does X work" questions.

CONSTRAINTS:
  Load Inter + JetBrains Mono from fonts.googleapis.com
  Load Chart.js from cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js
  No Tailwind. No other frameworks. Pure HTML + CSS + JS only.
  All CSS in one <style> block at top of <head>.
  All JavaScript in one <script> block at end of <body>.
  No separate CSS files, no separate JS files.
  Must look correct at 1366×768 (typical college lab monitor resolution).
  Must work in Chrome and Firefox with no extensions.
```

---

### Phase 3 Test Checklist

- [ ] `python dashboard/app.py` starts, no import errors, shows "Running on http://localhost:5000"
- [ ] localhost:5000 in browser → shows Start Exam modal (if no session) or dashboard (if session exists)
- [ ] Fill question + name, click Start → modal disappears, header shows question, timer starts
- [ ] All 5 stat cards show correct numbers (verify against SQLite)
- [ ] Score chart renders (red line, dark fill area)
- [ ] Keystroke velocity bars visible — red bar if any rate > 20/s
- [ ] Score breakdown shows which rules fired and how many points
- [ ] Activity timeline shows all events, newest first, flagged rows have red left border
- [ ] [Flagged only] toggle filters correctly
- [ ] DNS top domains shows correct domains and counts
- [ ] Window focus time shows correct apps and durations
- [ ] Dashboard auto-refreshes (watch the event count go up while agent is running)
- [ ] /about page loads and shows all sections correctly
- [ ] 1366×768 resolution test: nothing overflows, no horizontal scroll

---

## PHASE 4 — Gemini Flash AI Verdict

**Goal:** Click "Ask AI" → real Gemini verdict appears on screen in under 10 seconds.
**You know it's done when:** The verdict cites specific events from the actual log.

---

### PASTE THIS INTO YOUR AI IDE FOR PHASE 4

```
Add Gemini Flash AI verdict to LabShield.

PROJECT CONTEXT:
LabShield is a single-PC exam surveillance system, 7th semester project.
Teacher clicks "Ask AI for Verdict" on the dashboard.
The full activity log is sent to Gemini Flash.
Gemini returns a structured JSON verdict.
No AI/ML libraries — just HTTP requests to the Gemini API.

BUILD dashboard/ai_verdict.py:

FUNCTION get_ai_verdict(exam_question, activity_log_rows, total_score) → dict

  Step 1: Format the activity log into readable text
    Take the last 60 events (to stay within Gemini token limits)
    Each row formatted as:
      "HH:MM:SS | event_type | detail [+Xpts LABEL]"
    Example:
      "09:14:22 | dns_query | chatgpt.com [+40pts AI Tool]"
      "09:15:03 | clipboard_paste | Length: 340 chars | Preview: def solve..."
    Join all rows with newline.

  Step 2: Count statistics
    total_events = len(activity_log_rows)
    flagged_count = sum(1 for e in activity_log_rows if e['flagged'])
    ai_tool_events = sum(1 for e in activity_log_rows if 'AI Tool' in (e.get('label') or ''))

  Step 3: Build the prompt (exact text below):
"You are a strict college practical exam proctor analysing a student's
PC activity log to determine if they cheated.
Be objective and evidence-based. Cite only events that actually appear in the log.
Respond ONLY in valid JSON — no preamble, no markdown fences.

EXAM CONTEXT:
  Question: {exam_question}
  Total Suspicion Score: {total_score}
  Total Events: {total_events}
  Flagged Events: {flagged_count}
  AI Tool Accesses: {ai_tool_events}

ACTIVITY LOG (last 60 events, chronological):
{formatted_log}

Respond with ONLY this JSON structure, nothing else:
{{
  "verdict": "LIKELY CHEATED" | "POSSIBLY CHEATED" | "LIKELY CLEAN",
  "reason": "2-3 sentences citing specific timestamps and events from the log as evidence",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "key_evidence": ["most damning specific event 1", "specific event 2", "specific event 3"]
}}"

  Step 4: Call Gemini API
    URL: https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}
    Method: POST
    Header: Content-Type: application/json
    Body: {"contents": [{"parts": [{"text": full_prompt}]}]}
    Timeout: 15 seconds
    Use requests library (already in requirements.txt)

  Step 5: Parse response
    response_json = response.json()
    text = response_json['candidates'][0]['content']['parts'][0]['text']
    Strip any ```json and ``` fences from text
    Parse as JSON
    Return the dict

  ERROR HANDLING (return these dicts, never raise):
    Missing API key:  {verdict:"ERROR", reason:"GEMINI_API_KEY not set in config.py. Get a free key from https://aistudio.google.com/app/apikey", confidence:"", key_evidence:[]}
    Timeout:          {verdict:"ERROR", reason:"Gemini did not respond within 15 seconds. Check internet connection.", confidence:"", key_evidence:[]}
    JSON parse fail:  {verdict:"ERROR", reason:"Could not parse Gemini response. Raw: " + text[:200], confidence:"", key_evidence:[]}
    HTTP error:       {verdict:"ERROR", reason:"Gemini API returned status " + str(response.status_code), confidence:"", key_evidence:[]}
    Any exception:    {verdict:"ERROR", reason:"Unexpected error: " + str(e), confidence:"", key_evidence:[]}

In dashboard/app.py, POST /api/verdict:
  1. Read ALL events from DB via database.get_all_events()
  2. Read current session via database.get_current_session()
  3. Get total score via database.get_total_score()
  4. Call ai_verdict.get_ai_verdict(session['question'], events, total_score)
  5. Return JSON response directly (Flask jsonify)

CONSTRAINTS:
  Use requests library only — no openai SDK, no google-generativeai SDK.
  GEMINI_API_KEY comes from config.py only — never hardcoded.
  Empty API key → friendly error dict, no crash, no exception propagation.
  All errors are caught, logged to errors.log, and returned as error dicts.
```

---

### Phase 4 Test Checklist

- [ ] Set GEMINI_API_KEY in `agent/config.py` (get free key from aistudio.google.com)
- [ ] With events in SQLite, click "Ask AI" on dashboard → loading state appears in Card D
- [ ] Verdict appears in Card D within 15 seconds (no page navigation)
- [ ] Verdict text cites actual events from the log (not generic)
- [ ] One of: "LIKELY CHEATED" / "POSSIBLY CHEATED" / "LIKELY CLEAN"
- [ ] Key evidence shows 3 specific events with timestamps
- [ ] Remove API key from config → friendly error shown in Card D, no crash, no 500 error
- [ ] Test with only clean events in DB → should return "LIKELY CLEAN"
- [ ] Test with chatgpt.com + large clipboard paste → should return "LIKELY CHEATED"

---

## PHASE 5 — Polish + Demo Ready

**Goal:** The system is fully demo-ready. Launcher scripts, text export, README, and About page work perfectly.
**You know it's done when:** A complete stranger can clone the repo and run it following only the README.

---

### PASTE THIS INTO YOUR AI IDE FOR PHASE 5

```
Polish LabShield for demo and final submission. 7th semester college project.

PROJECT CONTEXT:
All 4 prior phases complete. Tech stack: Python agent + Flask + SQLite + Gemini API.
No new dependencies. Everything must work on a fresh Windows machine with:
  pip install -r requirements.txt
  (run.bat to start agent, start_dashboard.bat to open dashboard)

CREATE labshield/run.bat:
  @echo off
  echo ============================================
  echo   LabShield v1.0 — Exam Surveillance Agent
  echo ============================================
  echo.
  echo NOTE: Run as Administrator for DNS monitoring
  echo       (Right-click this file → Run as administrator)
  echo.
  cd /d %~dp0
  python -m agent.main
  pause

CREATE labshield/run.sh:
  #!/bin/bash
  echo "============================================"
  echo "  LabShield v1.0 — Exam Surveillance Agent"
  echo "============================================"
  echo ""
  echo "NOTE: DNS monitoring requires sudo"
  sudo python3 -m agent.main

CREATE labshield/start_dashboard.bat:
  @echo off
  echo Starting LabShield dashboard...
  cd /d %~dp0
  start "" http://localhost:5000
  python dashboard/app.py

CREATE labshield/start_dashboard.sh:
  #!/bin/bash
  echo "Starting LabShield dashboard..."
  sleep 2 && open http://localhost:5000 &  # macOS
  python3 dashboard/app.py

GET /export route in dashboard/app.py:
  Generate a downloadable .txt report with this exact format:

  ================================================
  LABSHIELD EXAM REPORT
  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  ================================================
  Student:         {student_name or "Not provided"}
  Exam Question:   {question}
  Session Start:   {started_at}
  Session End:     {ended_at or "Still running"}
  Duration:        {duration} minutes
  ------------------------------------------------
  VERDICT SUMMARY
  Total Suspicion Score: {total_score}
  Risk Level:            {score_label} ({score_color.upper()})
  Total Events:          {event_count}
  Flagged Events:        {flagged_count}
  HMAC Verified:         All {event_count} events signed
  ------------------------------------------------
  FLAGGED EVENTS (chronological)
  {for each flagged event:}
  [{timestamp}] {event_type} | {detail} | +{points}pts {label}
  ------------------------------------------------
  FULL ACTIVITY LOG
  {for each event:}
  [{timestamp}] {event_type} | {detail}
  ================================================
  END OF REPORT — LabShield v1.0

  Return with:
    Content-Type: text/plain
    Content-Disposition: attachment; filename="labshield_report_{student_name}_{date}.txt"

CREATE labshield/README.md:
  # LabShield — Exam Surveillance System

  Section: What is LabShield (2 paragraphs)
  Section: Quick Start (numbered steps — install, run agent, run dashboard)
  Section: How to Get Gemini API Key (exact steps + link)
  Section: What Each Monitor Detects (one bullet per monitor, brief)
  Section: Suspicion Score Guide (green/yellow/red table)
  Section: Tech Stack (same table from Section 3 of this document)
  Section: Folder Structure (the tree from Section 4)
  Section: Future Scope — 8th Semester (brief description of distributed version)
  Section: Notes for Viva (link to /about page, key talking points)

VERIFY about.html (from Phase 3) has these sections if not already built:
  About LabShield (what + why)
  Detection Methods (one card per monitor — what it catches and how)
  Why DNS Sniffing Catches Incognito (explain clearly — for viva)
  Why HMAC Signing Matters (tamper-proof evidence)
  Why Keystroke Velocity Detects Paste (explain the logic)
  Tech Stack Table
  Future Scope: 8th Semester Upgrade

CONSTRAINTS:
  No new pip packages.
  run.bat and start_dashboard.bat must work on Windows 10/11.
  Report .txt must be downloadable in both Chrome and Firefox.
  README must be readable without any markdown renderer.
```

---

### Phase 5 Test Checklist

- [ ] `run.bat` opens console, shows startup banner, starts monitoring
- [ ] `start_dashboard.bat` opens Flask AND auto-opens http://localhost:5000 in browser
- [ ] Click "Export Report" → browser downloads a .txt file
- [ ] Open the .txt — all sections present, correct data, correct format
- [ ] README.md — follow it as if you've never seen the project → can you get it running?
- [ ] /about page — read it → can you answer these viva questions from it:
  - "How does DNS sniffing catch incognito mode?"
  - "What is HMAC signing and why did you use it?"
  - "Why does keystroke velocity detect paste?"
  - "What would you change in 8th semester?"
- [ ] Full demo flow: Start exam → generate events → open dashboard → Ask AI → Export Report

---

# SECTION 8: SECURITY

| What | How | Why |
|---|---|---|
| Log tamper detection | HMAC-SHA256 signs every SQLite row | Proves logs weren't modified after the exam |
| API key protection | GEMINI_API_KEY in config.py only | Never in code or committed to git |
| Error logging | All exceptions to logs/errors.log | Audit trail + debugging |
| .gitignore | Ignore data/, logs/, config.py | Never commit DB or API keys |

`.gitignore` contents (create this):
```
data/
logs/
*.pyc
__pycache__/
.env
config.py
*.db
```

---

# SECTION 9: 8TH SEMESTER UPGRADE PATH

| Feature | 7th Sem (Done) | 8th Sem (Upgrade) |
|---|---|---|
| Monitoring scope | Single student PC | 60 student PCs simultaneously |
| Data storage | Local SQLite file | Central PostgreSQL on teacher's server |
| Communication | None (same machine) | WebSocket streaming via FastAPI |
| Dashboard | Flask at localhost | React dashboard hosted on teacher's machine |
| Caching | Not needed | Redis for live state of 60 students |
| Deployment | python run.bat | Docker + Nginx |
| Authentication | None (single PC) | JWT token login for teacher |
| AI verdicts | One student at a time | Batch processing for all 60 students |

**What stays exactly the same (zero changes needed):**
- All 6 monitor modules
- Rule engine logic
- Gemini Flash AI integration
- Database schema (PostgreSQL uses identical structure)
- Dashboard design (React renders the same UI)

**How to explain this in your viva:**
"In 7th semester, I proved the concept on a single PC — all detection methods
work correctly and the AI verdict is accurate. In 8th semester, the same agent
gets deployed to 60 PCs, streams data to a central server via WebSocket, and
the teacher gets a live view of all 60 students on one screen simultaneously.
The single-PC architecture was designed specifically to make this upgrade easy —
every module is independent and the database schema requires no changes."

---

# SECTION 10: GENERAL AI IDE RULES

> **Paste these at the very start of EVERY new AI IDE session, before the phase prompt.**
> Copy the block below exactly.

```
GENERAL RULES FOR ALL LABSHIELD SESSIONS:

1. Project: LabShield — 7th semester college exam surveillance system.
   Single PC version. ONE student PC. ONE teacher dashboard. NOT distributed.

2. Tech stack is FIXED. Do not suggest alternatives:
   Agent:     Python 3.11+ | Scapy | pygetwindow | watchdog | psutil | pyperclip | pynput
   Database:  SQLite (built-in, no server, no setup)
   Dashboard: Flask | plain HTML + CSS | Chart.js CDN (no Tailwind)
   AI:        Gemini Flash API via HTTP requests (no AI SDK libraries)
   NO React. NO FastAPI. NO PostgreSQL. NO Redis. NO Docker. NO WebSocket.
   These are planned for 8th semester. Do not suggest them.

3. Always create actual files on disk at the correct paths.
   Never just show code in the chat without creating the file.
   If you show code in chat, I will ask you to create the file again.

4. Never hardcode secrets. GEMINI_API_KEY lives in agent/config.py only.

5. Every Python exception must be caught and written to logs/errors.log.
   Format: "{datetime.now().isoformat()} | {monitor_name} | ERROR: {str(e)}"
   The agent must never fully crash. One monitor failing does not stop others.

6. All monitor threads must be daemon threads (daemon=True).
   main.py keeps running with: while True: time.sleep(1)

7. After every file you create, tell me:
   - How to test it (exact command or action)
   - What the expected output should be
   - One thing that could go wrong and how to fix it

8. Code must be clean enough for a college viva:
   - Every function needs a docstring
   - Every non-obvious line needs an inline comment
   - Variable names must be descriptive (not x, y, tmp)

9. Dashboard design (follow exactly):
   Background: #0d1117 | Cards: #161b22 | Border: 0.5px #21262d
   Text: #e6edf3 | Muted: #8b949e | Green: #3fb950 | Yellow: #d29922
   Red: #f85149 | Blue: #58a6ff | Purple: #bc8cff
   Fonts: Inter (UI) + JetBrains Mono (data/numbers)
   No gradients. No shadows. No glow. No Tailwind. Pure CSS.

10. When in doubt: simpler is better.
    Single PC, local use, college demo. Complexity comes in 8th semester.
```

---

> **LabShield** — Single PC. 7th Semester. Solid foundation.
> Every cheat leaves a trace. LabShield finds it.
> 8th semester: deploy to 60 PCs. 🚀
