"""
Keystroke velocity monitor — counts keypresses only, never logs key content.
Detects paste-like bursts when typing rate exceeds human norms.
"""

import os
import time
from datetime import datetime

from pynput import keyboard

from agent import config, database, security

MONITOR_NAME = "keystroke_monitor"


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


def _on_key_press(keypress_count: list) -> None:
    """
    pynput callback — increment counter only; never store key characters.

    Args:
        keypress_count: Single-element list used as mutable counter.
    """
    keypress_count[0] += 1


def _insert_keystroke_stats(rate: float, window_seconds: int, total_keys: int) -> None:
    """
    Sign and insert a keystroke_stats event for one measurement window.

    Args:
        rate: Keys per second over the window.
        window_seconds: Length of the measurement window.
        total_keys: Total keypress count in the window.
    """
    detail = (
        f"Rate: {rate:.1f} keys/sec over {window_seconds}s window "
        f"| Total keys: {total_keys}"
    )
    flagged = 0
    points = 0
    label = None
    if rate > config.KEYSTROKE_VELOCITY_THRESHOLD:
        flagged = 1
        points = 30
        label = "Paste Velocity"
    timestamp = datetime.now().isoformat()
    row_dict = {
        "timestamp": timestamp,
        "event_type": "keystroke_stats",
        "detail": detail,
    }
    hmac_sig = security.sign_row(row_dict)
    database.insert_event(
        timestamp=timestamp,
        event_type="keystroke_stats",
        detail=detail,
        flagged=flagged,
        points=points,
        label=label,
        hmac_sig=hmac_sig,
    )


def _run_velocity_windows(keypress_count: list, listener: keyboard.Listener) -> None:
    """
    Every KEYSTROKE_WINDOW seconds, compute rate and log stats.

    Args:
        keypress_count: Mutable counter list shared with key listener.
        listener: Active pynput keyboard listener.
    """
    window_seconds = config.KEYSTROKE_WINDOW
    while listener.running:
        time.sleep(window_seconds)
        total_keys = keypress_count[0]
        rate = total_keys / window_seconds if window_seconds > 0 else 0.0
        _insert_keystroke_stats(rate, window_seconds, total_keys)
        keypress_count[0] = 0


def run_keystroke_monitor() -> None:
    """
    Start pynput listener and velocity measurement loop; never exits.
    """
    while True:
        try:
            keypress_count = [0]
            listener = keyboard.Listener(
                on_press=lambda _key: _on_key_press(keypress_count),
            )
            listener.start()
            _run_velocity_windows(keypress_count, listener)
        except Exception as caught_error:
            _log_monitor_error(caught_error)
            time.sleep(5)


def start_keystroke_monitor() -> None:
    """
    Start the keystroke monitor in a daemon thread.
    """
    import threading

    monitor_thread = threading.Thread(
        target=run_keystroke_monitor,
        name="keystroke_monitor",
        daemon=True,
    )
    monitor_thread.start()
