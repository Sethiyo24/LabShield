"""
Gemini Flash AI verdict integration for LabShield exam sessions.
Includes interactive chat support: ask_ai_question() lets teachers
pose free-form questions about any session using the full activity log.
"""

import json
import os
import re
from datetime import datetime

import requests

from agent import config

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-flash:generateContent?key={api_key}"
)


def _log_ai_error(error: Exception) -> None:
    """
    Append an AI verdict exception to logs/errors.log.

    Args:
        error: The caught exception instance.
    """
    log_dir = os.path.dirname(config.LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    error_line = (
        f"{datetime.now().isoformat()} | ai_verdict | ERROR: {str(error)}\n"
    )
    with open(config.LOG_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(error_line)


def _parse_iso_timestamp(timestamp_text: str) -> datetime | None:
    """
    Parse an ISO8601 timestamp string safely.

    Args:
        timestamp_text: Timestamp from an activity log row.

    Returns:
        Parsed datetime or None.
    """
    try:
        return datetime.fromisoformat(timestamp_text)
    except (ValueError, TypeError):
        return None


def _format_event_line(event: dict) -> str:
    """
    Format one activity log row as a readable timeline line.

    Args:
        event: Activity log dict from SQLite.

    Returns:
        Single-line summary for the Gemini prompt.
    """
    event_dt = _parse_iso_timestamp(event.get("timestamp", ""))
    time_label = event_dt.strftime("%H:%M:%S") if event_dt else event.get("timestamp", "")
    suffix = ""
    if event.get("flagged") and event.get("points"):
        label_text = event.get("label") or ""
        suffix = f" [+{event['points']}pts {label_text}]"
    return f"{time_label} | {event['event_type']} | {event['detail']}{suffix}"


def _build_paste_history(activity_rows: list[dict]) -> str:
    """
    Build a clipboard paste summary block for the Gemini prompt.

    Args:
        activity_rows: All activity rows for the session.

    Returns:
        Multi-line paste history text.
    """
    paste_rows = [
        row for row in activity_rows if row.get("event_type") == "clipboard_paste"
    ]
    if not paste_rows:
        return "No clipboard paste events recorded."
    lines = []
    for row in paste_rows:
        lines.append(_format_event_line(row))
    return "\n".join(lines)


def _build_dns_summary(activity_rows: list[dict]) -> str:
    """
    Build a websites visited summary from DNS query events.

    Args:
        activity_rows: All activity rows for the session.

    Returns:
        Multi-line DNS summary text.
    """
    counts: dict[str, int] = {}
    for row in activity_rows:
        if row.get("event_type") != "dns_query":
            continue
        domain = row.get("detail", "").strip().lower()
        counts[domain] = counts.get(domain, 0) + 1
    if not counts:
        return "No DNS queries recorded."
    sorted_domains = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return "\n".join(f"{domain} — {count} queries" for domain, count in sorted_domains)


def _build_window_summary(activity_rows: list[dict]) -> str:
    """
    Build an apps-used summary with approximate focus durations.

    Args:
        activity_rows: All activity rows for the session.

    Returns:
        Multi-line window focus summary text.
    """
    window_events = [
        row for row in activity_rows if row.get("event_type") == "window_change"
    ]
    if len(window_events) < 2:
        return "Insufficient window focus data."
    focus_map: dict[str, float] = {}
    for index in range(len(window_events) - 1):
        current = window_events[index]
        next_event = window_events[index + 1]
        start_dt = _parse_iso_timestamp(current.get("timestamp", ""))
        end_dt = _parse_iso_timestamp(next_event.get("timestamp", ""))
        if start_dt is None or end_dt is None:
            continue
        seconds = max(0.0, (end_dt - start_dt).total_seconds())
        app_name = current.get("detail", "Unknown")
        focus_map[app_name] = focus_map.get(app_name, 0.0) + seconds
    if not focus_map:
        return "No app focus durations calculated."
    sorted_apps = sorted(focus_map.items(), key=lambda item: item[1], reverse=True)
    lines = []
    for app_name, seconds in sorted_apps:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        lines.append(f"{app_name} — {minutes}m {secs}s")
    return "\n".join(lines)


def _strip_json_fences(text: str) -> str:
    """
    Remove markdown code fences from a Gemini JSON response.

    Args:
        text: Raw model output text.

    Returns:
        Cleaned JSON string.
    """
    cleaned = text.strip()
    cleaned = re.sub(r"^```json\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^```\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def get_ai_verdict(
    session_name: str,
    student_name: str,
    exam_question: str,
    duration_minutes: float,
    activity_log_rows: list[dict],
    total_score: int,
) -> dict:
    """
    Request a structured Gemini Flash verdict for one exam session.

    Args:
        session_name: Sidebar display name for the session.
        student_name: Student identifier from the session row.
        exam_question: Exam question text.
        duration_minutes: Session duration in minutes.
        activity_log_rows: All activity rows for the session.
        total_score: Total suspicion score after rules.

    Returns:
        Verdict dict suitable for JSON API response.
    """
    if not config.GEMINI_API_KEY:
        return {
            "verdict": "ERROR",
            "reason": (
                "GEMINI_API_KEY not set in config.py. "
                "Get a free key from https://aistudio.google.com/app/apikey"
            ),
            "confidence": "",
            "key_evidence": [],
            "main_activities": [],
            "cheating_indicators": [],
            "judgment": "",
        }

    formatted_log = "\n".join(
        _format_event_line(row) for row in activity_log_rows
    ) or "No activity recorded."
    paste_history = _build_paste_history(activity_log_rows)
    dns_summary = _build_dns_summary(activity_log_rows)
    window_summary = _build_window_summary(activity_log_rows)
    total_events = len(activity_log_rows)

    prompt = f"""You are a college practical exam proctor.
Analyse this complete exam session log and identify all suspicious activity.
Be specific about timestamps and patterns.

Session: {session_name}
Student: {student_name or "Not provided"}
Exam Question: {exam_question}
Duration: {duration_minutes} minutes
Total Events: {total_events}
Suspicion Score: {total_score}

Complete Activity Log:
{formatted_log}

Clipboard Paste History:
{paste_history}

Websites Visited:
{dns_summary}

Apps Used (with time):
{window_summary}

Respond ONLY with this JSON:
{{
  "verdict": "LIKELY CHEATED" or "POSSIBLY CHEATED" or "LIKELY CLEAN",
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "reason": "3-4 sentences with specific timestamps",
  "main_activities": ["activity 1", "activity 2", "activity 3"],
  "cheating_indicators": ["specific evidence 1", "specific evidence 2"],
  "judgment": "One clear final sentence: guilty or not and why."
}}"""

    try:
        response = requests.post(
            GEMINI_URL.format(api_key=config.GEMINI_API_KEY),
            headers={"Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=15,
        )
        if response.status_code != 200:
            return {
                "verdict": "ERROR",
                "reason": f"Gemini API returned status {response.status_code}",
                "confidence": "",
                "key_evidence": [],
                "main_activities": [],
                "cheating_indicators": [],
                "judgment": "",
            }
        response_json = response.json()
        text = response_json["candidates"][0]["content"]["parts"][0]["text"]
        cleaned = _strip_json_fences(text)
        verdict_dict = json.loads(cleaned)
        verdict_dict.setdefault("key_evidence", verdict_dict.get("cheating_indicators", []))
        return verdict_dict
    except requests.Timeout:
        return {
            "verdict": "ERROR",
            "reason": "Gemini did not respond within 15 seconds. Check internet connection.",
            "confidence": "",
            "key_evidence": [],
            "main_activities": [],
            "cheating_indicators": [],
            "judgment": "",
        }
    except (json.JSONDecodeError, KeyError, IndexError) as parse_error:
        raw_text = locals().get("text", "")[:200]
        _log_ai_error(parse_error)
        return {
            "verdict": "ERROR",
            "reason": f"Could not parse Gemini response. Raw: {raw_text}",
            "confidence": "",
            "key_evidence": [],
            "main_activities": [],
            "cheating_indicators": [],
            "judgment": "",
        }
    except Exception as caught_error:
        _log_ai_error(caught_error)
        return {
            "verdict": "ERROR",
            "reason": f"Unexpected error: {str(caught_error)}",
            "confidence": "",
            "key_evidence": [],
            "main_activities": [],
            "cheating_indicators": [],
            "judgment": "",
        }


def ask_ai_question(
    question: str,
    session_name: str,
    student_name: str,
    exam_question: str,
    duration_minutes: float,
    activity_log_rows: list[dict],
    total_score: int,
) -> str:
    """
    Answer a free-form teacher question about an exam session using Gemini Flash.

    The full activity log is included as context so the model can answer
    specific questions like "Did the student open any browser?",
    "What did they paste?", or "How suspicious is the timing?"

    Args:
        question: Teacher's natural-language question.
        session_name: Sidebar display name for the session.
        student_name: Student identifier from the session row.
        exam_question: Original exam question text.
        duration_minutes: Session duration in minutes.
        activity_log_rows: All activity rows for the session.
        total_score: Total suspicion score after rules.

    Returns:
        Plain-text answer string from Gemini, or an error message.
    """
    if not config.GEMINI_API_KEY:
        return (
            "GEMINI_API_KEY not set in config.py. "
            "Get a free key from https://aistudio.google.com/app/apikey"
        )

    formatted_log = "\n".join(
        _format_event_line(row) for row in activity_log_rows
    ) or "No activity recorded."
    paste_history = _build_paste_history(activity_log_rows)
    dns_summary = _build_dns_summary(activity_log_rows)
    window_summary = _build_window_summary(activity_log_rows)
    total_events = len(activity_log_rows)

    system_context = f"""You are an intelligent exam monitoring assistant for a college practical exam.
You have access to the complete monitoring data for the session below.
Answer the teacher's question accurately using this data. Be concise but specific.
Reference timestamps and event details where relevant.

Session: {session_name}
Student: {student_name or "Not provided"}
Exam Question: {exam_question}
Duration: {duration_minutes} minutes
Total Events: {total_events}
Suspicion Score: {total_score}

Complete Activity Log:
{formatted_log}

Clipboard Paste History:
{paste_history}

Websites Visited (DNS Queries):
{dns_summary}

Apps Used (with focus time):
{window_summary}

Teacher's Question: {question}

Answer the question directly and concisely. Do NOT output JSON. Use plain text."""

    try:
        response = requests.post(
            GEMINI_URL.format(api_key=config.GEMINI_API_KEY),
            headers={"Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": system_context}]}]},
            timeout=20,
        )
        if response.status_code != 200:
            return f"Gemini API error (status {response.status_code}). Check your API key."
        response_json = response.json()
        return response_json["candidates"][0]["content"]["parts"][0]["text"].strip()
    except requests.Timeout:
        return "Gemini did not respond within 20 seconds. Check your internet connection."
    except (KeyError, IndexError) as parse_error:
        _log_ai_error(parse_error)
        return "Could not parse Gemini response. Please try again."
    except Exception as caught_error:
        _log_ai_error(caught_error)
        return f"Unexpected error: {str(caught_error)}"
