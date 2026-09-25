"""
File system monitor — watches Desktop, Documents, home, and USB drive paths
for code file opens and USB file access using watchdog.
"""

import os
import time
from datetime import datetime

from watchdog.events import FileModifiedEvent, FileOpenedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from agent import config, database, security

MONITOR_NAME = "file_monitor"

# Paths already logged this session — prevents duplicate watchdog events
already_logged: set[str] = set()

# Extensions that trigger code-file suspicion
CODE_EXTENSIONS = {".py", ".java", ".c", ".cpp", ".js", ".txt", ".docx"}

# Temp/log suffixes to skip (noise)
SKIP_SUFFIXES = (".log", ".tmp", "~")

# USB drive letter prefixes on Windows
USB_PATH_PREFIXES = ("D:\\", "E:\\", "F:\\", "G:\\")


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


def _should_skip_path(file_path: str) -> bool:
    """
    Return True if path is a log/temp file we should ignore or belongs to the project/system.

    Args:
        file_path: Full path to the file.

    Returns:
        True to skip this path.
    """
    abs_path = os.path.abspath(file_path).lower()
    proj_root = os.path.abspath(config.PROJECT_ROOT).lower()
    # Skip any files inside the project folder (including DB and logs) to avoid self-monitoring loops
    if abs_path.startswith(proj_root):
        return True
    # Skip system/agent sandbox paths used for testing and recording
    if ".gemini" in abs_path or "antigravity-ide" in abs_path or "jetski" in abs_path:
        return True
    return any(abs_path.endswith(suffix) for suffix in SKIP_SUFFIXES)


def _score_file_path(file_path: str) -> tuple[int, int, str | None]:
    """
    Determine suspicion flags for a file path.

    Args:
        file_path: Full path to the accessed file.

    Returns:
        Tuple of (flagged, points, label).
    """
    flagged = 0
    points = 0
    label = None
    _, extension = os.path.splitext(file_path)
    if extension.lower() in CODE_EXTENSIONS:
        flagged = 1
        points = 25
        label = "Code File Accessed"
    normalized = file_path.replace("/", "\\")
    for usb_prefix in USB_PATH_PREFIXES:
        if normalized.upper().startswith(usb_prefix.upper()):
            flagged = 1
            points = 25
            label = "USB File Access"
            break
    return flagged, points, label


def _insert_file_event(file_path: str) -> None:
    """
    Sign and insert a file_open event.

    Args:
        file_path: Full path of the opened or modified file.
    """
    if file_path in already_logged:
        return
    flagged, points, label = _score_file_path(file_path)
    timestamp = datetime.now().isoformat()
    row_dict = {
        "timestamp": timestamp,
        "event_type": "file_open",
        "detail": file_path,
    }
    hmac_sig = security.sign_row(row_dict)
    inserted = database.insert_event(
        timestamp=timestamp,
        event_type="file_open",
        detail=file_path,
        flagged=flagged,
        points=points,
        label=label,
        hmac_sig=hmac_sig,
    )
    if inserted:
        already_logged.add(file_path)


class LabShieldFileHandler(FileSystemEventHandler):
    """Watchdog handler that logs file open and modify events."""

    def on_opened(self, event: FileOpenedEvent) -> None:
        """
        Handle file opened events from watchdog.

        Args:
            event: Watchdog FileOpenedEvent.
        """
        if event.is_directory:
            return
        if _should_skip_path(event.src_path):
            return
        _insert_file_event(event.src_path)

    def on_modified(self, event: FileModifiedEvent) -> None:
        """
        Handle file modified events from watchdog.

        Args:
            event: Watchdog FileModifiedEvent.
        """
        if event.is_directory:
            return
        if _should_skip_path(event.src_path):
            return
        _insert_file_event(event.src_path)


def _build_watch_paths() -> list[str]:
    """
    Build list of directories to watch, including USB drives if present.

    Returns:
        List of absolute directory paths.
    """
    watch_paths = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~"),
    ]
    for drive_letter in ("D:\\", "E:\\", "F:\\", "G:\\"):
        if os.path.exists(drive_letter):
            watch_paths.append(drive_letter)
    return watch_paths


def _start_observer() -> Observer:
    """
    Create watchdog Observer and schedule handlers on all watch paths.

    Returns:
        Running Observer instance.
    """
    event_handler = LabShieldFileHandler()
    observer = Observer()
    home_dir = os.path.abspath(os.path.expanduser("~")).lower()
    for watch_path in _build_watch_paths():
        if os.path.isdir(watch_path):
            abs_watch = os.path.abspath(watch_path).lower()
            # Watch home directory non-recursively to avoid AppData noise/performance issues
            is_recursive = abs_watch != home_dir
            observer.schedule(event_handler, watch_path, recursive=is_recursive)
    observer.start()
    return observer


def run_file_monitor() -> None:
    """
    Run file system observer loop; restart on errors after 5 second sleep.
    """
    while True:
        observer = None
        try:
            observer = _start_observer()
            while observer.is_alive():
                time.sleep(1)
        except Exception as caught_error:
            _log_monitor_error(caught_error)
            time.sleep(5)
        finally:
            if observer is not None:
                observer.stop()
                observer.join(timeout=5)


def start_file_monitor() -> None:
    """
    Start the file monitor in a daemon thread.
    """
    import threading

    monitor_thread = threading.Thread(
        target=run_file_monitor,
        name="file_monitor",
        daemon=True,
    )
    monitor_thread.start()
