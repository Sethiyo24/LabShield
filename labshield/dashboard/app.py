"""
LabShield Flask dashboard — teacher view at localhost:5000.
Serves HTML pages and JSON APIs backed by SQLite activity logs.
"""

import os
import re
import sys
from datetime import datetime
from functools import wraps

# Project root (labshield/) — must be on sys.path before agent imports
APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_ROOT)
os.chdir(APP_ROOT)

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from agent import config, database
from dashboard import rules

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY


def _log_dashboard_error(error: Exception) -> None:
    """
    Write a dashboard exception to logs/errors.log without crashing the server.

    Args:
        error: The caught exception instance.
    """
    log_dir = os.path.dirname(config.LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    error_line = (
        f"{datetime.now().isoformat()} | dashboard | ERROR: {str(error)}\n"
    )
    with open(config.LOG_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(error_line)


def _request_agent_shutdown() -> None:
    """
    Write a shutdown flag file so the monitoring agent can exit gracefully.
    """
    flag_dir = os.path.dirname(config.SHUTDOWN_FLAG_PATH)
    if flag_dir:
        os.makedirs(flag_dir, exist_ok=True)
    with open(config.SHUTDOWN_FLAG_PATH, "w", encoding="utf-8") as flag_file:
        flag_file.write(datetime.now().isoformat())


def _parse_session_id() -> int | None:
    """
    Parse optional session_id from query string or JSON body.

    Returns:
        Integer session id or None when not provided.
    """
    raw_value = request.args.get("session_id")
    if raw_value is None and request.is_json:
        body = request.get_json(silent=True) or {}
        raw_value = body.get("session_id")
    if raw_value in (None, ""):
        return None
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return None


def login_required(view_func):
    """
    Decorator that redirects unauthenticated users to the login page.

    Args:
        view_func: Flask view function to protect.

    Returns:
        Wrapped view function.
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login_page"))
        return view_func(*args, **kwargs)

    return wrapped_view


def _parse_iso_timestamp(timestamp_text: str) -> datetime | None:
    """
    Parse an ISO8601 timestamp string into a datetime object.

    Args:
        timestamp_text: ISO8601 string from the database.

    Returns:
        Parsed datetime, or None if parsing fails.
    """
    try:
        return datetime.fromisoformat(timestamp_text)
    except (ValueError, TypeError):
        return None


def _format_duration_minutes(start_text: str, end_text: str | None) -> float:
    """
    Compute exam duration in minutes from start and optional end timestamps.

    Args:
        start_text: Session started_at ISO string.
        end_text: Session ended_at ISO string, or None if still running.

    Returns:
        Duration in minutes (float), or 0.0 if timestamps invalid.
    """
    start_dt = _parse_iso_timestamp(start_text)
    if start_dt is None:
        return 0.0
    end_dt = _parse_iso_timestamp(end_text) if end_text else datetime.now()
    if end_dt is None:
        return 0.0
    elapsed_seconds = max(0.0, (end_dt - start_dt).total_seconds())
    return round(elapsed_seconds / 60.0, 1)


def _build_session_payload(session_row: dict | None) -> dict | None:
    """
    Build session JSON for /api/score from a database session row.

    Args:
        session_row: Latest exam_session dict, or None.

    Returns:
        Session payload dict, or None when no session exists.
    """
    if session_row is None:
        return None
    duration = _format_duration_minutes(
        session_row["started_at"],
        session_row.get("ended_at"),
    )
    return {
        "id": session_row["id"],
        "session_name": session_row.get("session_name") or "Exam Session",
        "question": session_row["question"],
        "student_name": session_row.get("student_name") or "",
        "started_at": session_row["started_at"],
        "ended_at": session_row.get("ended_at"),
        "duration_minutes": duration,
    }


def _parse_keystroke_rate(detail_text: str) -> float:
    """
    Extract keys-per-second rate from a keystroke_stats detail string.

    Args:
        detail_text: e.g. 'Rate: 12.3 keys/sec over 5s window | Total keys: 61'

    Returns:
        Parsed rate as float, or 0.0 if not found.
    """
    match = re.search(r"Rate:\s*([\d.]+)\s*keys/sec", detail_text)
    if match:
        return float(match.group(1))
    return 0.0


def _parse_paste_length(detail_text: str) -> int:
    """
    Extract character length from a clipboard_paste detail string.

    Args:
        detail_text: e.g. 'Length: 340 chars | Preview: ...'

    Returns:
        Parsed length as int, or 0 if not found.
    """
    match = re.search(r"Length:\s*(\d+)\s*chars", detail_text)
    if match:
        return int(match.group(1))
    return 0


def _parse_paste_preview(detail_text: str) -> str:
    """
    Extract preview text from a clipboard_paste detail string (display only).

    Args:
        detail_text: Clipboard event detail from SQLite.

    Returns:
        Preview text for the history list (first 80 chars).
    """
    match = re.search(r"Preview:\s*(.*?)(?:\|\s*Content:|$)", detail_text, re.DOTALL)
    preview = match.group(1).strip() if match else detail_text
    return preview[:80]


def _parse_paste_full_content(detail_text: str) -> str:
    """
    Extract the full pasted text from a clipboard_paste detail string.

    Args:
        detail_text: Clipboard event detail from SQLite.

    Returns:
        Complete paste content without truncation.
    """
    match = re.search(r"Content:\s*(.*)", detail_text, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r"Preview:\s*(.*)", detail_text, re.DOTALL)
    return match.group(1).strip() if match else detail_text


def _compute_clipboard_stats(events: list[dict]) -> tuple[int, int, int]:
    """
    Count clipboard events, flagged pastes, and largest paste size.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        Tuple of (clipboard_count, flagged_count, largest_paste_chars).
    """
    clipboard_events = [e for e in events if e["event_type"] == "clipboard_paste"]
    flagged_count = sum(1 for e in clipboard_events if e.get("flagged"))
    largest = 0
    for event in clipboard_events:
        paste_len = _parse_paste_length(event["detail"])
        largest = max(largest, paste_len)
    return len(clipboard_events), flagged_count, largest


def _compute_clipboard_history(events: list[dict]) -> list[dict]:
    """
    Build ordered clipboard paste history for the session analytics panel.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        List of paste history dicts ordered chronologically.
    """
    clipboard_events = [
        event for event in events if event["event_type"] == "clipboard_paste"
    ]
    history = []
    for event in clipboard_events:
        history.append({
            "timestamp": event["timestamp"],
            "char_count": _parse_paste_length(event["detail"]),
            "preview": _parse_paste_preview(event["detail"]),
            "full_content": _parse_paste_full_content(event["detail"]),
            "flagged": bool(event.get("flagged")),
            "label": event.get("label"),
            "points": event.get("points") or 0,
        })
    return history


def _compute_keystroke_stats(events: list[dict]) -> tuple[int, float]:
    """
    Count keystroke windows and compute average typing rate.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        Tuple of (keystroke_count, avg_keystroke_rate).
    """
    keystroke_events = [e for e in events if e["event_type"] == "keystroke_stats"]
    if not keystroke_events:
        return 0, 0.0
    rates = [_parse_keystroke_rate(e["detail"]) for e in keystroke_events]
    avg_rate = sum(rates) / len(rates)
    return len(keystroke_events), round(avg_rate, 1)


def _compute_top_domains(events: list[dict]) -> list[dict]:
    """
    Aggregate DNS queries and return top 10 domains by query count.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        List of domain stat dicts sorted by count descending.
    """
    domain_map: dict[str, dict] = {}
    for event in events:
        if event["event_type"] != "dns_query":
            continue
        domain = event["detail"].strip().lower()
        if domain not in domain_map:
            domain_map[domain] = {
                "domain": domain,
                "count": 0,
                "points": event.get("points") or 0,
                "label": event.get("label"),
                "flagged": bool(event.get("flagged")),
            }
        domain_map[domain]["count"] += 1
        if event.get("points", 0) > domain_map[domain]["points"]:
            domain_map[domain]["points"] = event["points"]
            domain_map[domain]["label"] = event.get("label")
        if event.get("flagged"):
            domain_map[domain]["flagged"] = True
    sorted_domains = sorted(domain_map.values(), key=lambda d: d["count"], reverse=True)
    return sorted_domains[:10]


def _compute_websites_visited(events: list[dict]) -> list[dict]:
    """
    Summarize all DNS domains visited during a session.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        List of website summary dicts sorted by visit count.
    """
    domain_map: dict[str, dict] = {}
    for event in events:
        if event["event_type"] != "dns_query":
            continue
        domain = event["detail"].strip().lower()
        if domain not in domain_map:
            domain_map[domain] = {
                "domain": domain,
                "count": 0,
                "flagged": bool(event.get("flagged")),
                "label": event.get("label"),
            }
        domain_map[domain]["count"] += 1
        if event.get("flagged"):
            domain_map[domain]["flagged"] = True
    return sorted(domain_map.values(), key=lambda item: item["count"], reverse=True)


def _compute_apps_used(events: list[dict]) -> list[dict]:
    """
    Summarize apps opened from window_change events with visit counts.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        List of app usage dicts sorted by visit count descending.
    """
    app_map: dict[str, dict] = {}
    for event in events:
        if event["event_type"] != "window_change":
            continue
        app_name = event["detail"]
        if app_name not in app_map:
            app_map[app_name] = {
                "app": app_name,
                "count": 0,
                "seconds": 0.0,
                "flagged": False,
            }
        app_map[app_name]["count"] += 1
        if event.get("flagged"):
            app_map[app_name]["flagged"] = True
    focus_rows = _compute_window_focus(events)
    for focus_row in focus_rows:
        app_name = focus_row["app"]
        if app_name in app_map:
            app_map[app_name]["seconds"] = focus_row["seconds"]
    result = list(app_map.values())
    result.sort(key=lambda row: row["count"], reverse=True)
    return result


def _compute_search_queries(events: list[dict]) -> list[dict]:
    """
    Build search query list from search_query activity rows.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        List of {term, timestamp, flagged} dicts ordered chronologically.
    """
    search_events = [
        event for event in events if event["event_type"] == "search_query"
    ]
    return [
        {
            "term": event["detail"],
            "timestamp": event["timestamp"],
            "flagged": bool(event.get("flagged")),
        }
        for event in search_events
    ]


def _compute_window_focus(events: list[dict]) -> list[dict]:
    """
    Compute time spent in each window title from consecutive window_change events.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        List of {app, seconds, flagged} sorted by seconds descending.
    """
    window_events = [e for e in events if e["event_type"] == "window_change"]
    if len(window_events) < 2:
        return []
    focus_map: dict[str, dict] = {}
    for index in range(len(window_events) - 1):
        current = window_events[index]
        next_event = window_events[index + 1]
        start_dt = _parse_iso_timestamp(current["timestamp"])
        end_dt = _parse_iso_timestamp(next_event["timestamp"])
        if start_dt is None or end_dt is None:
            continue
        seconds = max(0.0, (end_dt - start_dt).total_seconds())
        app_name = current["detail"]
        if app_name not in focus_map:
            focus_map[app_name] = {"app": app_name, "seconds": 0.0, "flagged": False}
        focus_map[app_name]["seconds"] += seconds
        if current.get("flagged"):
            focus_map[app_name]["flagged"] = True
    result = list(focus_map.values())
    result.sort(key=lambda row: row["seconds"], reverse=True)
    for row in result:
        row["seconds"] = round(row["seconds"], 1)
    return result


def _format_elapsed_label(seconds_from_start: float) -> str:
    """
    Format seconds from session start as MM:SS for chart labels.

    Args:
        seconds_from_start: Elapsed seconds since exam start.

    Returns:
        Label string like '05:00'.
    """
    total_seconds = int(seconds_from_start)
    minutes = total_seconds // 60
    seconds = total_seconds % 60
    return f"{minutes:02d}:{seconds:02d}"


def _compute_score_history(
    events: list[dict],
    session_start_text: str | None,
) -> list[dict]:
    """
    Build cumulative score datapoints from scored events in chronological order.

    Args:
        events: Activity log rows for the selected session.
        session_start_text: Session started_at ISO string.

    Returns:
        List of {time, cumulative_score} for the line chart.
    """
    history = [{"time": "00:00", "cumulative_score": 0}]
    scored_events = [
        event for event in events if (event.get("points") or 0) > 0
    ]
    scored_events.sort(key=lambda row: row["timestamp"])
    session_start = _parse_iso_timestamp(session_start_text)
    cumulative = 0
    for event in scored_events:
        cumulative += event.get("points") or 0
        event_dt = _parse_iso_timestamp(event["timestamp"])
        if session_start and event_dt:
            elapsed = max(0.0, (event_dt - session_start).total_seconds())
            label = _format_elapsed_label(elapsed)
        elif event_dt:
            label = event_dt.strftime("%H:%M:%S")
        else:
            label = event["timestamp"]
        history.append({"time": label, "cumulative_score": cumulative})
    return history


def _compute_keystroke_history(events: list[dict]) -> list[dict]:
    """
    Return the last 8 keystroke_stats windows for velocity bar chart.

    Args:
        events: Activity log rows for the selected session.

    Returns:
        List of {timestamp, rate, flagged} dicts.
    """
    keystroke_events = [e for e in events if e["event_type"] == "keystroke_stats"]
    last_eight = keystroke_events[-8:]
    history = []
    for event in last_eight:
        event_dt = _parse_iso_timestamp(event["timestamp"])
        time_label = event_dt.strftime("%H:%M:%S") if event_dt else event["timestamp"]
        history.append({
            "timestamp": time_label,
            "rate": _parse_keystroke_rate(event["detail"]),
            "flagged": bool(event.get("flagged")),
        })
    return history


def _resolve_session_id(requested_id: int | None) -> int | None:
    """
    Resolve the session id used for analytics.

    Prefers the client-selected session, then the open active session,
    then the most recent historical session.

    Args:
        requested_id: Session id from the client, if any.

    Returns:
        Effective session id or None.
    """
    if requested_id is not None:
        return requested_id
    open_id = database.get_open_session_id()
    if open_id is not None:
        return open_id
    current = database.get_current_session()
    return int(current["id"]) if current else None


def _build_score_payload(session_id: int | None = None) -> dict:
    """
    Assemble the full /api/score JSON payload after running the rule engine.

    Args:
        session_id: Optional session to scope analytics.

    Returns:
        Complete score statistics dict for the dashboard frontend.
    """
    effective_id = _resolve_session_id(session_id)
    total_score = rules.run_rules_on_all_events(session_id=effective_id)
    events = (
        database.get_session_events(effective_id)
        if effective_id is not None
        else database.get_all_events()
    )
    session_row = (
        database.get_session_by_id(effective_id)
        if effective_id is not None
        else database.get_current_session()
    )
    keystroke_count, avg_rate = _compute_keystroke_stats(events)
    clip_count, clip_flagged, largest_paste = _compute_clipboard_stats(events)
    dns_count = sum(1 for e in events if e["event_type"] == "dns_query")
    usb_events = sum(
        1 for e in events if e["event_type"] in ("usb_mount", "usb_unmount")
    )
    flagged_count = sum(1 for e in events if e.get("flagged"))
    session_start = session_row["started_at"] if session_row else None
    return {
        "session_id": effective_id,
        "total_score": total_score,
        "score_color": rules.get_score_color(total_score),
        "score_label": rules.get_score_label(total_score),
        "chart_y_max": max(total_score * 1.2, 10),
        "event_count": len(events),
        "flagged_count": flagged_count,
        "keystroke_count": keystroke_count,
        "avg_keystroke_rate": avg_rate,
        "clipboard_count": clip_count,
        "clipboard_flagged_count": clip_flagged,
        "largest_paste_chars": largest_paste,
        "dns_count": dns_count,
        "usb_events": usb_events,
        "top_domains": _compute_top_domains(events),
        "window_focus": _compute_window_focus(events),
        "apps_used": _compute_apps_used(events),
        "websites_visited": _compute_websites_visited(events),
        "clipboard_history": _compute_clipboard_history(events),
        "search_queries": _compute_search_queries(events),
        "score_history": _compute_score_history(events, session_start),
        "session": _build_session_payload(session_row),
        "keystroke_history": _compute_keystroke_history(events),
        "score_breakdown": database.get_score_breakdown(session_id=effective_id),
    }


def _serialize_events_newest_first(events: list[dict]) -> list[dict]:
    """
    Convert DB event rows to API JSON format, newest first.

    Args:
        events: Activity log rows from the database.

    Returns:
        List of event dicts for /api/events.
    """
    sorted_events = sorted(
        events,
        key=lambda row: row["timestamp"],
        reverse=True,
    )
    return [
        {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "detail": row["detail"],
            "full_detail": row["detail"],
            "full_content": (
                _parse_paste_full_content(row["detail"])
                if row["event_type"] == "clipboard_paste"
                else row["detail"]
            ),
            "flagged": bool(row.get("flagged")),
            "points": row.get("points") or 0,
            "label": row.get("label"),
        }
        for row in sorted_events
    ]


def _generate_export_report(session_id: int | None = None) -> str:
    """
    Build a plain-text exam report for the /export download route.

    Args:
        session_id: Optional session to export.

    Returns:
        Full report string in the LabShield export format.
    """
    effective_id = _resolve_session_id(session_id)
    rules.run_rules_on_all_events(session_id=effective_id)
    events = (
        database.get_session_events(effective_id)
        if effective_id is not None
        else database.get_all_events()
    )
    session_row = (
        database.get_session_by_id(effective_id)
        if effective_id is not None
        else database.get_current_session()
    )
    total_score = database.get_total_score(session_id=effective_id)
    flagged_events = [e for e in events if e.get("flagged")]
    event_count = len(events)
    score_color = rules.get_score_color(total_score)
    score_label = rules.get_score_label(total_score)
    student_name = (session_row or {}).get("student_name") or "Not provided"
    question = (session_row or {}).get("question") or "Not provided"
    started_at = (session_row or {}).get("started_at") or "Unknown"
    ended_at = (session_row or {}).get("ended_at") or "Still running"
    duration = _format_duration_minutes(
        started_at if started_at != "Unknown" else "",
        session_row.get("ended_at") if session_row else None,
    )
    lines = [
        "================================================",
        "LABSHIELD EXAM REPORT",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "================================================",
        f"Student:         {student_name}",
        f"Exam Question:   {question}",
        f"Session Start:   {started_at}",
        f"Session End:     {ended_at}",
        f"Duration:        {duration} minutes",
        "------------------------------------------------",
        "VERDICT SUMMARY",
        f"Total Suspicion Score: {total_score}",
        f"Risk Level:            {score_label} ({score_color.upper()})",
        f"Total Events:          {event_count}",
        f"Flagged Events:        {len(flagged_events)}",
        f"HMAC Verified:         All {event_count} events signed",
        "------------------------------------------------",
        "FLAGGED EVENTS (chronological)",
    ]
    for event in flagged_events:
        label_text = event.get("label") or ""
        lines.append(
            f"[{event['timestamp']}] {event['event_type']} | "
            f"{event['detail']} | +{event.get('points', 0)}pts {label_text}"
        )
    lines.append("------------------------------------------------")
    lines.append("FULL ACTIVITY LOG")
    for event in events:
        lines.append(
            f"[{event['timestamp']}] {event['event_type']} | {event['detail']}"
        )
    lines.append("================================================")
    lines.append("END OF REPORT — LabShield v1.0")
    return "\n".join(lines)


@app.route("/login", methods=["GET"])
def login_page():
    """
    Render the password login page.

    Returns:
        Rendered login.html template.
    """
    if session.get("authenticated"):
        return redirect(url_for("index_page"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_submit():
    """
    Verify dashboard password and start an authenticated Flask session.

    Returns:
        JSON success response or error payload.
    """
    try:
        body = request.get_json(silent=True) or {}
        password = (body.get("password") or "").strip()
        if password == config.DASHBOARD_PASSWORD:
            session["authenticated"] = True
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Incorrect password"}), 401
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"success": False, "error": str(caught_error)}), 500


@app.route("/logout")
def logout_page():
    """
    Clear the authenticated session and redirect to login.

    Returns:
        Redirect response to /login.
    """
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def index_page():
    """
    Render the main teacher dashboard page.

    Returns:
        Rendered index.html template.
    """
    return render_template("index.html")


@app.route("/about")
@login_required
def about_page():
    """
    Render the about / viva preparation page.

    Returns:
        Rendered about.html template.
    """
    return render_template("about.html")


@app.route("/api/sessions")
@login_required
def api_sessions():
    """
    Return all exam sessions for the sidebar list.

    Returns:
        JSON list of session summary dicts.
    """
    try:
        sessions = database.get_all_sessions()
        for session_row in sessions:
            session_row["score_color"] = rules.get_score_color(
                int(session_row.get("total_score") or 0)
            )
        return jsonify(sessions)
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"error": str(caught_error)}), 500


@app.route("/api/score")
@login_required
def api_score():
    """
    Return full dashboard statistics JSON; refreshes rule scores first.

    Returns:
        JSON response with all score and session metrics.
    """
    try:
        return jsonify(_build_score_payload(session_id=_parse_session_id()))
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"error": str(caught_error)}), 500


@app.route("/api/events")
@login_required
def api_events():
    """
    Return activity events as JSON, newest first.

    Returns:
        JSON list of event dicts.
    """
    try:
        session_id = _parse_session_id()
        effective_id = _resolve_session_id(session_id)
        events = (
            database.get_session_events(effective_id)
            if effective_id is not None
            else database.get_recent_events(limit=500)
        )
        return jsonify(_serialize_events_newest_first(events))
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"error": str(caught_error)}), 500


@app.route("/api/start", methods=["POST"])
@login_required
def api_start():
    """
    Create a new exam session from JSON body.

    Returns:
        JSON {success: true, session_id} or error response.
    """
    try:
        body = request.get_json(silent=True) or {}
        question = (body.get("question") or "").strip()
        student_name = (body.get("student_name") or "").strip()
        session_name = (body.get("session_name") or "Exam Session").strip()
        if not question:
            return jsonify({"success": False, "error": "Exam question is required"}), 400
        if os.path.exists(config.SHUTDOWN_FLAG_PATH):
            os.remove(config.SHUTDOWN_FLAG_PATH)
        database.init_db()
        database.end_all_open_sessions()
        session_id = database.create_session(question, student_name, session_name)
        session["selected_session_id"] = session_id
        return jsonify({"success": True, "session_id": session_id})
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"success": False, "error": str(caught_error)}), 500


@app.route("/api/end", methods=["POST"])
@login_required
def api_end():
    """
    End the current exam session after password confirmation.

    Returns:
        JSON {success: true} or error response.
    """
    try:
        body = request.get_json(silent=True) or {}
        password = (body.get("password") or "").strip()
        if password != config.DASHBOARD_PASSWORD:
            return jsonify({"success": False, "error": "Wrong password"}), 401
        session_id = body.get("session_id")
        parsed_id = int(session_id) if session_id is not None else None
        database.end_session(session_id=parsed_id)
        _request_agent_shutdown()
        session.pop("selected_session_id", None)
        return jsonify({"success": True})
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"success": False, "error": str(caught_error)}), 500


@app.route("/api/session/rename", methods=["POST"])
@login_required
def api_session_rename():
    """
    Rename an exam session from JSON body {session_id, new_name}.

    Returns:
        JSON success response.
    """
    try:
        body = request.get_json(silent=True) or {}
        session_id = body.get("session_id")
        new_name = (body.get("new_name") or "").strip()
        if not session_id or not new_name:
            return jsonify({"success": False, "error": "session_id and new_name required"}), 400
        updated = database.rename_session(int(session_id), new_name)
        if not updated:
            return jsonify({"success": False, "error": "Session not found"}), 404
        return jsonify({"success": True})
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"success": False, "error": str(caught_error)}), 500


@app.route("/api/session/delete", methods=["POST"])
@login_required
def api_session_delete():
    """
    Delete an exam session and all its events after password confirmation.

    Returns:
        JSON {success: true} or error response.
    """
    try:
        body = request.get_json(silent=True) or {}
        password = (body.get("password") or "").strip()
        if password != config.DASHBOARD_PASSWORD:
            return jsonify({"success": False, "error": "Wrong password"}), 401
        session_id = body.get("session_id")
        if session_id is None:
            return jsonify({"success": False, "error": "session_id required"}), 400
        parsed_id = int(session_id)
        deleted = database.delete_session(parsed_id)
        if not deleted:
            return jsonify({"success": False, "error": "Session not found"}), 404
        if session.get("selected_session_id") == parsed_id:
            session.pop("selected_session_id", None)
        return jsonify({"success": True})
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"success": False, "error": str(caught_error)}), 500


@app.route("/api/ai/chat", methods=["POST"])
@login_required
def api_ai_chat():
    """
    Answer a teacher's free-form question about one exam session using Gemini.

    Expects JSON body: {session_id, question}

    Returns:
        JSON {answer: str} or error.
    """
    try:
        body = request.get_json(silent=True) or {}
        session_id = body.get("session_id")
        question = (body.get("question") or "").strip()
        if not question:
            return jsonify({"error": "question is required"}), 400
        effective_id = _resolve_session_id(
            int(session_id) if session_id is not None else None
        )
        rules.run_rules_on_all_events(session_id=effective_id)
        events = (
            database.get_session_events(effective_id)
            if effective_id is not None
            else database.get_all_events()
        )
        session_row = (
            database.get_session_by_id(effective_id)
            if effective_id is not None
            else database.get_current_session()
        )
        total_score = database.get_total_score(session_id=effective_id)
        from dashboard.ai_verdict import ask_ai_question

        answer = ask_ai_question(
            question=question,
            session_name=(session_row or {}).get("session_name") or "Exam Session",
            student_name=(session_row or {}).get("student_name") or "",
            exam_question=(session_row or {}).get("question") or "",
            duration_minutes=_format_duration_minutes(
                (session_row or {}).get("started_at", ""),
                (session_row or {}).get("ended_at"),
            ),
            activity_log_rows=events,
            total_score=total_score,
        )
        return jsonify({"answer": answer})
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({"error": str(caught_error)}), 500


@app.route("/api/verdict", methods=["POST"])
@login_required
def api_verdict():
    """
    Request an AI verdict for one exam session activity log.

    Returns:
        JSON verdict dict from Gemini or an error dict.
    """
    try:
        body = request.get_json(silent=True) or {}
        session_id = body.get("session_id")
        effective_id = _resolve_session_id(
            int(session_id) if session_id is not None else None
        )
        rules.run_rules_on_all_events(session_id=effective_id)
        events = (
            database.get_session_events(effective_id)
            if effective_id is not None
            else database.get_all_events()
        )
        session_row = (
            database.get_session_by_id(effective_id)
            if effective_id is not None
            else database.get_current_session()
        )
        total_score = database.get_total_score(session_id=effective_id)
        from dashboard.ai_verdict import get_ai_verdict

        verdict = get_ai_verdict(
            session_name=(session_row or {}).get("session_name") or "Exam Session",
            student_name=(session_row or {}).get("student_name") or "",
            exam_question=(session_row or {}).get("question") or "",
            duration_minutes=_format_duration_minutes(
                (session_row or {}).get("started_at", ""),
                (session_row or {}).get("ended_at"),
            ),
            activity_log_rows=events,
            total_score=total_score,
        )
        return jsonify(verdict)
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return jsonify({
            "verdict": "ERROR",
            "reason": str(caught_error),
            "confidence": "",
            "key_evidence": [],
            "main_activities": [],
            "cheating_indicators": [],
            "judgment": "",
        }), 500


@app.route("/export")
@login_required
def export_report():
    """
    Download a plain-text exam report as an attachment.

    Returns:
        text/plain Response with Content-Disposition attachment header.
    """
    try:
        session_id = _parse_session_id()
        report_text = _generate_export_report(session_id=session_id)
        session_row = (
            database.get_session_by_id(session_id)
            if session_id is not None
            else database.get_current_session()
        )
        student_slug = (session_row or {}).get("student_name") or "student"
        student_slug = re.sub(r"[^\w\-]", "_", student_slug)
        date_slug = datetime.now().strftime("%Y%m%d")
        filename = f"labshield_report_{student_slug}_{date_slug}.txt"
        return Response(
            report_text,
            mimetype="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as caught_error:
        _log_dashboard_error(caught_error)
        return Response(
            f"Export failed: {str(caught_error)}",
            mimetype="text/plain",
            status=500,
        )


if __name__ == "__main__":
    database.init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
