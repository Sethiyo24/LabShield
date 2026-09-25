"""
Clipboard monitor — detects paste events by polling clipboard content changes.
"""

import os
import time
from datetime import datetime

import pyperclip

from agent import config, database, security

MONITOR_NAME = "clipboard_monitor"


def _log_monitor_error(error: Exception) -> None:
    """
    Append a formatted error line to logs/errors.log.

    Args:
        error: The caught exception instance.
    """
    log_dir = os.path.dirname(config.LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    error_line = (
        f"{datetime.now().isoformat()} | {MONITOR_NAME} | ERROR: {str(error)}\n"
    )
    with open(config.LOG_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(error_line)


def _read_clipboard_safe() -> str:
    """
    Read clipboard text; return empty string on failure (e.g. no xclip on Linux).

    Returns:
        Clipboard text content or empty string.
    """
    try:
        return pyperclip.paste() or ""
    except Exception:
        return ""


def _build_clipboard_detail(content: str) -> str:
    """
    Build human-readable detail string for a clipboard event.

    Args:
        content: Full clipboard text.

    Returns:
        Formatted detail with length and preview.
    """
    preview = content[:100].strip()
    # Store full content after Content: so the dashboard can show the complete paste
    return f"Length: {len(content)} chars | Preview: {preview} | Content: {content}"


def _insert_clipboard_event(content: str) -> None:
    """
    Sign and insert a clipboard_paste event with optional large-paste flag.

    Args:
        content: Clipboard text that changed.
    """
    detail = _build_clipboard_detail(content)
    flagged = 0
    points = 0
    label = None
    if len(content) > config.CLIPBOARD_FLAG_THRESHOLD:
        flagged = 1
        points = 30
        label = "Large Paste"
    timestamp = datetime.now().isoformat()
    row_dict = {
        "timestamp": timestamp,
        "event_type": "clipboard_paste",
        "detail": detail,
    }
    hmac_sig = security.sign_row(row_dict)
    database.insert_event(
        timestamp=timestamp,
        event_type="clipboard_paste",
        detail=detail,
        flagged=flagged,
        points=points,
        label=label,
        hmac_sig=hmac_sig,
    )


def run_clipboard_monitor() -> None:
    """
    Poll clipboard every 0.5 seconds; log when non-empty content changes.
    """
    previous_content = ""
    while True:
        try:
            current_content = _read_clipboard_safe()
            if current_content and current_content != previous_content:
                _insert_clipboard_event(current_content)
                previous_content = current_content
            time.sleep(0.5)
        except Exception as caught_error:
            _log_monitor_error(caught_error)
            time.sleep(5)


def start_clipboard_monitor() -> None:
    """
    Start the clipboard monitor in a daemon thread.
    """
    import threading

    monitor_thread = threading.Thread(
        target=run_clipboard_monitor,
        name="clipboard_monitor",
        daemon=True,
    )
    monitor_thread.start()
