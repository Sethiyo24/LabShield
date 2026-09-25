"""
HMAC signing and verification for tamper-proof activity log rows.
"""

import hmac
import hashlib

from agent import config


def sign_row(row_dict: dict) -> str:
    """
    Compute HMAC-SHA256 hex signature for a log row.

    Signs the concatenation of timestamp + event_type + detail.

    Args:
        row_dict: Dict with keys 'timestamp', 'event_type', 'detail'.

    Returns:
        Hex-encoded HMAC-SHA256 signature string.
    """
    # Build the message string exactly as specified in the spec
    message = (
        row_dict["timestamp"]
        + row_dict["event_type"]
        + row_dict["detail"]
    )
    secret_bytes = config.HMAC_SECRET.encode("utf-8")
    message_bytes = message.encode("utf-8")
    # HMAC-SHA256 produces a tamper-evident signature
    signature = hmac.new(secret_bytes, message_bytes, hashlib.sha256)
    return signature.hexdigest()


def verify_row(row_dict: dict, signature: str) -> bool:
    """
    Verify an HMAC signature against a log row using constant-time comparison.

    Args:
        row_dict: Dict with keys 'timestamp', 'event_type', 'detail'.
        signature: Stored HMAC hex string from the database.

    Returns:
        True if signature matches, False otherwise.
    """
    expected_signature = sign_row(row_dict)
    # compare_digest prevents timing attacks on signature checks
    return hmac.compare_digest(expected_signature, signature)
