"""
USB drive monitor — polls disk partitions every 2 seconds to detect
removable drive mount and unmount events.
"""

import os
import time
from datetime import datetime

import psutil

from agent import config, database, security

MONITOR_NAME = "usb_monitor"


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


def _partition_key(partition) -> str:
    """
    Build a unique string key for a disk partition.

    Args:
        partition: psutil partition named tuple.

    Returns:
        Unique key combining device and mountpoint.
    """
    return f"{partition.device}|{partition.mountpoint}"


def _is_removable_partition(partition) -> bool:
    """
    Return True if partition appears to be a removable USB drive.

    Args:
        partition: psutil partition named tuple.

    Returns:
        True for removable / non-fixed drives.
    """
    opts_lower = (partition.opts or "").lower()
    if "removable" in opts_lower:
        return True
    # Windows: fstype empty on some USB; also check drive letter beyond C:
    mountpoint = partition.mountpoint or ""
    if len(mountpoint) >= 2 and mountpoint[1] == ":":
        drive_letter = mountpoint[0].upper()
        # If this is the drive hosting the project, it's not a removable/USB drive for monitoring
        proj_drive = os.path.splitdrive(os.path.abspath(config.PROJECT_ROOT))[0].upper()
        if proj_drive.startswith(drive_letter):
            return False
        if drive_letter > "C":
            return True
    return False


def _get_removable_partitions() -> dict[str, object]:
    """
    Snapshot current removable partitions keyed by device|mountpoint.

    Returns:
        Dict mapping partition key to partition object.
    """
    removable = {}
    for partition in psutil.disk_partitions(all=True):
        if _is_removable_partition(partition):
            removable[_partition_key(partition)] = partition
    return removable


def _insert_usb_mount(partition) -> None:
    """
    Log a usb_mount event when a removable drive appears.

    Args:
        partition: psutil partition named tuple.
    """
    detail = (
        f"Drive {partition.device} mounted at {partition.mountpoint} "
        f"({partition.fstype})"
    )
    timestamp = datetime.now().isoformat()
    row_dict = {
        "timestamp": timestamp,
        "event_type": "usb_mount",
        "detail": detail,
    }
    hmac_sig = security.sign_row(row_dict)
    database.insert_event(
        timestamp=timestamp,
        event_type="usb_mount",
        detail=detail,
        flagged=0,
        points=0,
        label=None,
        hmac_sig=hmac_sig,
    )


def _insert_usb_unmount(device: str, mountpoint: str) -> None:
    """
    Log a usb_unmount event when a drive is removed.

    Args:
        device: Device path that was removed.
        mountpoint: Former mount point path.
    """
    detail = f"Drive {device} removed at {datetime.now().isoformat()}"
    timestamp = datetime.now().isoformat()
    row_dict = {
        "timestamp": timestamp,
        "event_type": "usb_unmount",
        "detail": detail,
    }
    hmac_sig = security.sign_row(row_dict)
    database.insert_event(
        timestamp=timestamp,
        event_type="usb_unmount",
        detail=detail,
        flagged=0,
        points=0,
        label=None,
        hmac_sig=hmac_sig,
    )


def _poll_usb_changes(known_partitions: dict[str, object]) -> dict[str, object]:
    """
    Compare current removable partitions to known set; log mount/unmount.

    Args:
        known_partitions: Previously seen removable partition dict.

    Returns:
        Updated known partition dict.
    """
    current = _get_removable_partitions()
    current_keys = set(current.keys())
    known_keys = set(known_partitions.keys())
    for new_key in current_keys - known_keys:
        _insert_usb_mount(current[new_key])
    for removed_key in known_keys - current_keys:
        removed = known_partitions[removed_key]
        _insert_usb_unmount(removed.device, removed.mountpoint)
    return current


def run_usb_monitor() -> None:
    """
    Poll disk partitions every 2 seconds for USB mount/unmount changes.
    """
    known_partitions = _get_removable_partitions()
    while True:
        try:
            known_partitions = _poll_usb_changes(known_partitions)
            time.sleep(2)
        except Exception as caught_error:
            _log_monitor_error(caught_error)
            time.sleep(5)


def start_usb_monitor() -> None:
    """
    Start the USB monitor in a daemon thread.
    """
    import threading

    monitor_thread = threading.Thread(
        target=run_usb_monitor,
        name="usb_monitor",
        daemon=True,
    )
    monitor_thread.start()
