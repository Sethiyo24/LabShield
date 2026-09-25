"""
Active window title monitor — polls every 1 second and logs title changes.
"""

import os
import time
from datetime import datetime

import pygetwindow as gw

from agent import config, database, security

MONITOR_NAME = "window_monitor"

# Window title keywords that indicate suspicious apps
SUSPICIOUS_KEYWORDS = (
    "Gmail",
    "Inbox",
    "Drafts",
    "Google Classroom",
    "Google Drive",
)

# Browser suffixes stripped to extract page title
BROWSER_SUFFIXES = (" - Google Chrome", " - Mozilla Firefox", " - Chrome", " - Firefox")

# IDE name fragments used to extract filename from title
IDE_NAMES = ("Visual Studio Code", "PyCharm", "Sublime Text", "IDLE")


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


def _get_active_window_title() -> str:
    """
    Return the current active window title using pygetwindow.

    Returns:
        Window title string, or empty string if none active.
    """
    # pygetwindow exposes getActiveWindow(); title is on the Window object
    active_window = gw.getActiveWindow()
    if active_window is None:
        return ""
    return active_window.title or ""


def _extract_title_detail(full_title: str) -> str:
    """
    Extract meaningful detail from a raw window title.

    Args:
        full_title: Complete window title from the OS.

    Returns:
        Cleaned title (page name, filename, or full title).
    """
    if not full_title:
        return ""
    # Browser: strip browser name suffix to get page title
    for browser_suffix in BROWSER_SUFFIXES:
        if full_title.endswith(browser_suffix):
            return full_title[: -len(browser_suffix)].strip()
    # IDE: title often starts with filename — use full title (contains filename)
    for ide_name in IDE_NAMES:
        if ide_name in full_title:
            return full_title
    return full_title


def _check_suspicious_title(title: str) -> tuple[int, int, str | None]:
    """
    Check title against suspicious keyword list.

    Args:
        title: Extracted window title detail.

    Returns:
        Tuple of (flagged, points, label) — (0,0,None) if clean.
    """
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in title.lower():
            return 1, 35, "Suspicious App"
    return 0, 0, None


def _extract_search_query(raw_title: str) -> str | None:
    """
    Extract a search term from a browser window title if present.

    Args:
        raw_title: Full active window title from the OS.

    Returns:
        Search term string, or None when the title is not a search results page.
    """
    if not raw_title:
        return None
    if " - Google Search" in raw_title:
        return raw_title.split(" - Google Search")[0].strip()
    if raw_title.startswith("Google - "):
        return raw_title[len("Google - ") :].strip()
    if " - Bing" in raw_title:
        return raw_title.split(" - Bing")[0].strip()
    if " at DuckDuckGo" in raw_title:
        return raw_title.split(" at DuckDuckGo")[0].strip()
    return None


def _insert_search_query_event(search_term: str) -> None:
    """
    Sign and insert a search_query event for a detected browser search.

    Args:
        search_term: Extracted query text from the window title.
    """
    if not search_term:
        return
    timestamp = datetime.now().isoformat()
    row_dict = {
        "timestamp": timestamp,
        "event_type": "search_query",
        "detail": search_term,
    }
    hmac_sig = security.sign_row(row_dict)
    database.insert_event(
        timestamp=timestamp,
        event_type="search_query",
        detail=search_term,
        flagged=1,
        points=15,
        label="Search Query",
        hmac_sig=hmac_sig,
    )


def _insert_window_event(detail: str, flagged: int, points: int, label: str | None) -> None:
    """
    Sign and insert a window_change event.

    Args:
        detail: Extracted window title detail.
        flagged: 1 if suspicious, 0 otherwise.
        points: Suspicion points.
        label: Event label or None.
    """
    timestamp = datetime.now().isoformat()
    row_dict = {
        "timestamp": timestamp,
        "event_type": "window_change",
        "detail": detail,
    }
    hmac_sig = security.sign_row(row_dict)
    database.insert_event(
        timestamp=timestamp,
        event_type="window_change",
        detail=detail,
        flagged=flagged,
        points=points,
        label=label,
        hmac_sig=hmac_sig,
    )


def run_window_monitor() -> None:
    """
    Poll active window every 1 second; log only when title changes.
    """
    previous_title = ""
    while True:
        try:
            raw_title = _get_active_window_title()
            detail = _extract_title_detail(raw_title)
            if detail and detail != previous_title:
                flagged, points, label = _check_suspicious_title(detail)
                _insert_window_event(detail, flagged, points, label)
                search_term = _extract_search_query(raw_title)
                if search_term:
                    _insert_search_query_event(search_term)
                previous_title = detail
            time.sleep(1)
        except Exception as caught_error:
            _log_monitor_error(caught_error)
            time.sleep(5)


def start_window_monitor() -> None:
    """
    Start the window monitor in a daemon thread.
    """
    import threading

    monitor_thread = threading.Thread(
        target=run_window_monitor,
        name="window_monitor",
        daemon=True,
    )
    monitor_thread.start()
