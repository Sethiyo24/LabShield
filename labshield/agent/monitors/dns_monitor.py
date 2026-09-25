"""
DNS query monitor — sniffs DNS packets with Scapy to catch all browsing,
including incognito mode (DNS cannot be hidden by browser privacy).
"""

import os
import time
from datetime import datetime

from agent import config, database, security

MONITOR_NAME = "dns_monitor"

# System DNS suffixes to ignore (local network noise)
SKIP_SUFFIXES = (".local", ".arpa", ".internal")


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


def _should_skip_domain(domain: str) -> bool:
    """
    Return True if domain is system noise and should not be logged.

    Args:
        domain: Lowercase domain without trailing dot.

    Returns:
        True to skip logging this domain.
    """
    return any(domain.endswith(suffix) for suffix in SKIP_SUFFIXES)


def _insert_dns_event(domain: str) -> None:
    """
    Sign and insert a dns_query event for the given domain.

    Args:
        domain: Queried domain name (lowercase, no trailing dot).
    """
    timestamp = datetime.now().isoformat()
    row_dict = {
        "timestamp": timestamp,
        "event_type": "dns_query",
        "detail": domain,
    }
    hmac_sig = security.sign_row(row_dict)
    database.insert_event(
        timestamp=timestamp,
        event_type="dns_query",
        detail=domain,
        flagged=0,
        points=0,
        label=None,
        hmac_sig=hmac_sig,
    )


def _handle_dns_packet(packet) -> None:
    """
    Extract queried domain from a Scapy DNS packet and log if valid.

    Args:
        packet: Scapy packet object from sniff callback.
    """
    # Only process packets that contain a DNS question record
    if not packet.haslayer("DNS") or not packet["DNS"].qr == 0:
        return
    if not packet["DNS"].qd:
        return
    raw_domain = packet["DNS"].qd.qname.decode("utf-8", errors="ignore")
    domain = raw_domain.rstrip(".").lower()
    if not domain or _should_skip_domain(domain):
        return
    _insert_dns_event(domain)


def _sniff_dns_loop() -> None:
    """
    Run Scapy DNS sniff until interrupted; errors are logged and retried.
    """
    from scapy.all import DNS, DNSQR, sniff  # noqa: F401 — DNSQR used by filter

    # BPF filter: only DNS query packets
    sniff(filter="udp port 53", prn=_handle_dns_packet, store=False)


def run_dns_monitor() -> None:
    """
    Main DNS monitor loop — never exits; catches errors and sleeps.
    """
    last_npcap_warning = 0.0
    while True:
        try:
            _sniff_dns_loop()
        except ImportError:
            _log_monitor_error(
                ImportError(
                    "DNS monitoring requires Scapy. Run as Administrator/root."
                )
            )
            time.sleep(5)
        except Exception as caught_error:
            err_msg = str(caught_error)
            if "winpcap is not installed" in err_msg or "npcap" in err_msg.lower():
                # Avoid spamming: only log once every 60 seconds
                now = time.time()
                if now - last_npcap_warning > 60:
                    _log_monitor_error(
                        RuntimeError(
                            "Npcap/WinPcap is not installed. DNS monitoring is disabled. "
                            "Please install Npcap from https://npcap.com/ to enable DNS query capture."
                        )
                    )
                    last_npcap_warning = now
                time.sleep(10)
            else:
                _log_monitor_error(caught_error)
                time.sleep(5)


def start_dns_monitor() -> None:
    """
    Start the DNS monitor in a daemon thread.
    """
    import threading

    monitor_thread = threading.Thread(
        target=run_dns_monitor,
        name="dns_monitor",
        daemon=True,
    )
    monitor_thread.start()


def is_scapy_available() -> bool:
    """
    Check whether Scapy can be imported for the startup banner.

    Returns:
        True if Scapy imports successfully.
    """
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False
