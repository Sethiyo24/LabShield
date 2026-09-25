"""
LabShield agent entry point — starts all monitors and keeps the process alive.
"""

import os
import signal
import time

from agent import config, database
from agent.monitors import (
    clipboard_monitor,
    dns_monitor,
    file_monitor,
    keystroke_monitor,
    usb_monitor,
    window_monitor,
)


def _print_startup_banner(dns_status: str) -> None:
    """
    Print the LabShield startup banner to the console.

    Args:
        dns_status: Human-readable DNS monitor status string.
    """
    student_display = config.STUDENT_NAME if config.STUDENT_NAME else "unnamed"
    print("====================================", flush=True)
    print("  LabShield v1.0 - Monitoring Active", flush=True)
    print("====================================", flush=True)
    print(f"  Student: {student_display}", flush=True)
    print(f"  Database: {config.DB_PATH}", flush=True)
    print(f"  DNS Monitor: {dns_status}", flush=True)
    print("  Window Monitor: Active", flush=True)
    print("  Clipboard Monitor: Active", flush=True)
    print("  Keystroke Monitor: Active", flush=True)
    print("  File Monitor: Active", flush=True)
    print("  USB Monitor: Active", flush=True)
    print("  Protected: stop via dashboard only", flush=True)


def _get_dns_status() -> str:
    """
    Determine DNS monitor status for the startup banner.

    Returns:
        'Active' if Scapy is available, else admin requirement message.
    """
    if dns_monitor.is_scapy_available():
        return "Active (run as Administrator for packet capture)"
    return "Requires Admin — Scapy not available"


def _start_all_monitors() -> None:
    """
    Launch all six monitoring threads as daemons.
    """
    dns_monitor.start_dns_monitor()
    window_monitor.start_window_monitor()
    clipboard_monitor.start_clipboard_monitor()
    keystroke_monitor.start_keystroke_monitor()
    file_monitor.start_file_monitor()
    usb_monitor.start_usb_monitor()


def _print_session_summary() -> None:
    """
    Print total events and suspicion score when session ends.
    """
    all_events = database.get_all_events()
    total_score = database.get_total_score()
    print("")
    print("Session ended.")
    print(f"  Total events logged: {len(all_events)}")
    print(f"  Total suspicion score: {total_score}")


def _clear_shutdown_flag() -> None:
    """
    Remove any stale shutdown flag before a new monitoring run starts.
    """
    if os.path.exists(config.SHUTDOWN_FLAG_PATH):
        os.remove(config.SHUTDOWN_FLAG_PATH)


def _shutdown_flag_requested() -> bool:
    """
    Check whether the dashboard requested a graceful agent shutdown.

    Returns:
        True when the shutdown flag file exists.
    """
    return os.path.exists(config.SHUTDOWN_FLAG_PATH)


def _handle_protected_signal(signum: int, _frame) -> None:
    """
    Ignore SIGINT/SIGTERM and instruct the teacher to use the dashboard.

    Args:
        signum: Received signal number.
        _frame: Current stack frame (unused).
    """
    print("LabShield is protected. Stop via dashboard only.", flush=True)


def _stop_agent_cleanly() -> None:
    """
    End the current session, remove the shutdown flag, and exit the process.
    """
    if os.path.exists(config.SHUTDOWN_FLAG_PATH):
        os.remove(config.SHUTDOWN_FLAG_PATH)
    database.end_session()
    _print_session_summary()
    print("LabShield stopped via dashboard.", flush=True)


def main() -> None:
    """
    Initialize database, create exam session, start monitors, block until shutdown.
    """
    signal.signal(signal.SIGINT, _handle_protected_signal)
    signal.signal(signal.SIGTERM, _handle_protected_signal)
    _clear_shutdown_flag()
    database.init_db()
    database.create_session(config.EXAM_QUESTION, config.STUDENT_NAME)
    dns_status = _get_dns_status()
    _print_startup_banner(dns_status)
    _start_all_monitors()
    while True:
        if _shutdown_flag_requested():
            _stop_agent_cleanly()
            break
        time.sleep(1)


if __name__ == "__main__":
    main()
