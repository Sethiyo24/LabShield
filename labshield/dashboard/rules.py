"""
LabShield suspicion scoring rule engine.
Maps DNS domains and window titles to points; updates SQLite rows in bulk.
"""

import os
import re
from datetime import datetime

from agent import config, database

# Score thresholds for green / yellow / red risk levels
SCORE_GREEN_MAX = 30
SCORE_YELLOW_MAX = 80
# 81+ is RED

# Online compiler domains — not auto-flagged; used for paste correlation only
ONLINE_COMPILER_DOMAINS: set[str] = {
    "programiz.com",
    "replit.com",
    "onecompiler.com",
    "colab.research.google.com",
    "jdoodle.com",
    "ideone.com",
    "compiler.io",
    "onlinegdb.com",
}

# Domain → (points, label) — one line per domain to add new detections
SUSPICIOUS_DOMAINS: dict[str, tuple[int, str]] = {
    # AI Tools — highest points, clearest evidence of cheating
    "chatgpt.com": (40, "AI Tool"),
    "chat.openai.com": (40, "AI Tool"),
    "gemini.google.com": (40, "AI Tool"),
    "claude.ai": (40, "AI Tool"),
    "copilot.microsoft.com": (40, "AI Tool"),
    "perplexity.ai": (35, "AI Tool"),
    "blackboxai.com": (35, "AI Tool"),
    "you.com": (35, "AI Tool"),
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
}


def _match_domain(domain: str, rule_domain: str) -> bool:
    """
    Check exact or subdomain suffix match for a suspicious domain rule.

    Args:
        domain: Queried domain (lowercase).
        rule_domain: Key from SUSPICIOUS_DOMAINS.

    Returns:
        True if domain equals or ends with '.' + rule_domain.
    """
    if domain == rule_domain:
        return True
    suffix = "." + rule_domain
    return domain.endswith(suffix)


def _is_compiler_domain(domain: str) -> bool:
    """
    Return True when a DNS domain belongs to an online compiler site.

    Args:
        domain: Queried domain name.

    Returns:
        True for known online compiler hosts.
    """
    normalized = domain.strip().lower().rstrip(".")
    for compiler_domain in ONLINE_COMPILER_DOMAINS:
        if _match_domain(normalized, compiler_domain):
            return True
    return False


def _parse_event_timestamp(timestamp_text: str) -> datetime | None:
    """
    Parse an ISO8601 event timestamp from the database.

    Args:
        timestamp_text: Timestamp string stored on an activity row.

    Returns:
        Parsed datetime or None when invalid.
    """
    try:
        return datetime.fromisoformat(timestamp_text)
    except (ValueError, TypeError):
        return None


def score_dns_event(domain: str) -> tuple[int, str | None]:
    """
    Score a DNS query domain against SUSPICIOUS_DOMAINS.

    Args:
        domain: Queried domain name.

    Returns:
        (points, label) if matched, else (0, None).
    """
    normalized = domain.strip().lower().rstrip(".")
    for rule_domain, (points, label) in SUSPICIOUS_DOMAINS.items():
        if _match_domain(normalized, rule_domain):
            return points, label
    return 0, None


def score_window_event(window_title: str) -> tuple[int, str | None]:
    """
    Score a window title against suspicious keyword rules.

    Args:
        window_title: Active window title text.

    Returns:
        (points, label) if matched, else (0, None).
    """
    title_lower = window_title.lower()
    gmail_keywords = ("gmail", "inbox", "drafts", "sent")
    for keyword in gmail_keywords:
        if keyword in title_lower:
            return 35, "Gmail Access"
    if "google classroom" in title_lower or "classroom.google" in title_lower:
        return 30, "Google Classroom"
    if "google drive" in title_lower or "drive.google" in title_lower:
        return 25, "Cloud Storage"
    return 0, None


def get_score_color(total_score: int) -> str:
    """
    Map total suspicion score to a color band name.

    Args:
        total_score: Sum of all event points.

    Returns:
        'green', 'yellow', or 'red'.
    """
    if total_score <= SCORE_GREEN_MAX:
        return "green"
    if total_score <= SCORE_YELLOW_MAX:
        return "yellow"
    return "red"


def get_score_label(total_score: int) -> str:
    """
    Map total suspicion score to a human-readable risk label.

    Args:
        total_score: Sum of all event points.

    Returns:
        'Clean', 'Suspicious', or 'High Risk'.
    """
    if total_score <= SCORE_GREEN_MAX:
        return "Clean"
    if total_score <= SCORE_YELLOW_MAX:
        return "Suspicious"
    return "High Risk"


def _apply_dns_rules(events: list[dict]) -> None:
    """
    Score all dns_query events and persist updates to the database.

    Args:
        events: Activity log rows for the current scoring scope.
    """
    pending_updates: list[tuple[int, int, str]] = []
    for event in events:
        if event["event_type"] != "dns_query":
            continue
        points, label = score_dns_event(event["detail"])
        if points > 0 and label is not None:
            pending_updates.append((event["id"], points, label))
    database.batch_update_event_scores(pending_updates)


def _apply_window_rules(events: list[dict]) -> None:
    """
    Score all window_change events and persist updates to the database.

    Args:
        events: Activity log rows for the current scoring scope.
    """
    pending_updates: list[tuple[int, int, str]] = []
    for event in events:
        if event["event_type"] != "window_change":
            continue
        points, label = score_window_event(event["detail"])
        if points > 0 and label is not None:
            pending_updates.append((event["id"], points, label))
    database.batch_update_event_scores(pending_updates)


def _parse_paste_length(detail_text: str) -> int:
    """
    Extract character count from a clipboard_paste detail string.

    Args:
        detail_text: Clipboard event detail from the database.

    Returns:
        Parsed character length, or 0 if not found.
    """
    match = re.search(r"Length:\s*(\d+)\s*chars", detail_text)
    return int(match.group(1)) if match else 0


def _parse_keystroke_rate(detail_text: str) -> float:
    """
    Extract keys-per-second rate from a keystroke_stats detail string.

    Args:
        detail_text: Keystroke event detail from the database.

    Returns:
        Parsed rate as float, or 0.0 if not found.
    """
    match = re.search(r"Rate:\s*([\d.]+)\s*keys/sec", detail_text)
    return float(match.group(1)) if match else 0.0


def _score_file_event(file_path: str) -> tuple[int, str | None]:
    """
    Apply file monitor scoring rules to a file path.

    Args:
        file_path: Full path of the accessed file.

    Returns:
        (points, label) if suspicious, else (0, None).
    """
    abs_path = os.path.abspath(file_path).lower()
    proj_root = os.path.abspath(config.PROJECT_ROOT).lower()
    if abs_path.startswith(proj_root):
        return 0, None
    if ".gemini" in abs_path or "antigravity-ide" in abs_path or "jetski" in abs_path:
        return 0, None

    code_extensions = {".py", ".java", ".c", ".cpp", ".js", ".txt", ".docx"}
    _, extension = os.path.splitext(file_path)
    if extension.lower() in code_extensions:
        return 25, "Code File Accessed"
    normalized = file_path.replace("/", "\\")
    for drive in ("D:\\", "E:\\", "F:\\", "G:\\"):
        if normalized.upper().startswith(drive.upper()):
            return 25, "USB File Access"
    return 0, None


def _apply_compiler_paste_combo(events: list[dict]) -> None:
    """
    Upgrade large pastes to Compiler + Paste Combo when compiler DNS precedes them.

    Args:
        events: Activity log rows for the current scoring scope.
    """
    dns_events = [
        event for event in events if event["event_type"] == "dns_query"
    ]
    pending_updates: list[tuple[int, int, str]] = []
    for event in events:
        if event["event_type"] != "clipboard_paste":
            continue
        if _parse_paste_length(event["detail"]) <= config.CLIPBOARD_FLAG_THRESHOLD:
            continue
        paste_time = _parse_event_timestamp(event["timestamp"])
        if paste_time is None:
            continue
        for dns_event in dns_events:
            dns_time = _parse_event_timestamp(dns_event["timestamp"])
            if dns_time is None:
                continue
            seconds_before = (paste_time - dns_time).total_seconds()
            if 0 <= seconds_before <= 120 and _is_compiler_domain(dns_event["detail"]):
                pending_updates.append(
                    (event["id"], 45, "Compiler + Paste Combo")
                )
                break
    database.batch_update_event_scores(pending_updates)


def _apply_agent_rules(events: list[dict]) -> None:
    """
    Re-apply monitor-level scoring for non-DNS event types after a reset.

    Args:
        events: Activity log rows for the current scoring scope.
    """
    pending_updates: list[tuple[int, int, str]] = []
    combo_paste_ids: set[int] = set()

    for event in events:
        if event["event_type"] != "clipboard_paste":
            continue
        if _parse_paste_length(event["detail"]) <= config.CLIPBOARD_FLAG_THRESHOLD:
            continue
        paste_time = _parse_event_timestamp(event["timestamp"])
        if paste_time is None:
            continue
        for dns_event in events:
            if dns_event["event_type"] != "dns_query":
                continue
            dns_time = _parse_event_timestamp(dns_event["timestamp"])
            if dns_time is None:
                continue
            seconds_before = (paste_time - dns_time).total_seconds()
            if 0 <= seconds_before <= 120 and _is_compiler_domain(dns_event["detail"]):
                combo_paste_ids.add(event["id"])
                pending_updates.append(
                    (event["id"], 45, "Compiler + Paste Combo")
                )
                break

    for event in events:
        event_type = event["event_type"]
        if event_type == "clipboard_paste":
            if event["id"] in combo_paste_ids:
                continue
            if _parse_paste_length(event["detail"]) > config.CLIPBOARD_FLAG_THRESHOLD:
                pending_updates.append((event["id"], 30, "Large Paste"))
        elif event_type == "keystroke_stats":
            if _parse_keystroke_rate(event["detail"]) > config.KEYSTROKE_VELOCITY_THRESHOLD:
                pending_updates.append((event["id"], 30, "Paste Velocity"))
        elif event_type == "file_open":
            points, label = _score_file_event(event["detail"])
            if points > 0 and label:
                pending_updates.append((event["id"], points, label))
        elif event_type == "search_query":
            pending_updates.append((event["id"], 15, "Search Query"))

    database.batch_update_event_scores(pending_updates)


def run_rules_on_all_events(session_id: int | None = None) -> int:
    """
    Reset labeled scores, rescore events fresh, return total suspicion score.

    Args:
        session_id: When set, only rescore events belonging to that session.

    Returns:
        Sum of points across the scoring scope after rules are applied.
    """
    database.reset_labeled_scores(session_id=session_id)
    events = (
        database.get_session_events(session_id)
        if session_id is not None
        else database.get_all_events()
    )
    _apply_dns_rules(events)
    _apply_window_rules(events)
    _apply_agent_rules(events)
    return database.get_total_score(session_id=session_id)
