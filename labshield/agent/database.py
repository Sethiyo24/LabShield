"""
Thread-safe SQLite database layer for LabShield activity logs and exam sessions.
"""

import os
import sqlite3
import threading
import time
from datetime import datetime

from agent import config

# Global lock — all writes must acquire this before touching the DB
_db_lock = threading.RLock()

# Dedup window for insert_event — key is event_type|detail, value is last insert time
_last_event: dict[str, float] = {}
DEDUP_SECONDS = 5


def _get_connection() -> sqlite3.Connection:
    """
    Open a SQLite connection with row factory for dict-like access.

    Returns:
        sqlite3.Connection pointed at config.DB_PATH.
    """
    db_dir = os.path.dirname(config.DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    connection = sqlite3.connect(config.DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _table_has_column(connection: sqlite3.Connection, table: str, column: str) -> bool:
    """
    Return True if a column already exists on a SQLite table.

    Args:
        connection: Open SQLite connection.
        table: Table name to inspect.
        column: Column name to look for.

    Returns:
        True when the column is present.
    """
    cursor = connection.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


def _migrate_schema(connection: sqlite3.Connection) -> None:
    """
    Add session_name and session_id columns to existing databases safely.

    Args:
        connection: Open SQLite connection with an active transaction.
    """
    if not _table_has_column(connection, "exam_session", "session_name"):
        connection.execute(
            'ALTER TABLE exam_session ADD COLUMN session_name TEXT DEFAULT "Exam Session"'
        )
    if not _table_has_column(connection, "activity_logs", "session_id"):
        connection.execute(
            "ALTER TABLE activity_logs ADD COLUMN session_id INTEGER"
        )


def init_db() -> None:
    """
    Create activity_logs and exam_session tables if they do not exist.
    """
    create_activity_logs = """
        CREATE TABLE IF NOT EXISTS activity_logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            event_type   TEXT NOT NULL,
            detail       TEXT NOT NULL,
            flagged      INTEGER DEFAULT 0,
            points       INTEGER DEFAULT 0,
            label        TEXT,
            hmac_sig     TEXT,
            session_id   INTEGER
        )
    """
    create_exam_session = """
        CREATE TABLE IF NOT EXISTS exam_session (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            question     TEXT NOT NULL,
            started_at   TEXT NOT NULL,
            ended_at     TEXT,
            student_name TEXT,
            session_name TEXT DEFAULT 'Exam Session'
        )
    """
    with _db_lock:
        connection = _get_connection()
        try:
            connection.execute(create_activity_logs)
            connection.execute(create_exam_session)
            _migrate_schema(connection)
            connection.commit()
        finally:
            connection.close()


def get_open_session_id() -> int | None:
    """
    Return the id of the currently active (not ended) exam session.

    Uses the most recently started open session. Returns None when every
    session has ended — callers must not attach events to a closed session.

    Returns:
        Open session id, or None when no active session exists.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            cursor = connection.execute(
                """
                SELECT id FROM exam_session
                WHERE ended_at IS NULL
                ORDER BY started_at DESC
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            return int(row["id"]) if row else None
        finally:
            connection.close()


def get_active_session_id() -> int | None:
    """
    Return the best session id for dashboard analytics resolution.

    Prefers the open session; falls back to the latest session row when all
    sessions are closed (for viewing historical data).

    Returns:
        Session id integer, or None when no sessions exist.
    """
    open_session_id = get_open_session_id()
    if open_session_id is not None:
        return open_session_id
    with _db_lock:
        connection = _get_connection()
        try:
            cursor = connection.execute(
                "SELECT id FROM exam_session ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            return int(row["id"]) if row else None
        finally:
            connection.close()


def insert_event(
    timestamp: str,
    event_type: str,
    detail: str,
    flagged: int,
    points: int,
    label: str | None,
    hmac_sig: str,
    session_id: int | None = None,
) -> bool:
    """
    Insert a signed activity log row (thread-safe) with 5-second deduplication.

    Args:
        timestamp: ISO8601 timestamp string.
        event_type: Event category (e.g. dns_query, window_change).
        detail: Human-readable event detail.
        flagged: 1 if suspicious, 0 otherwise.
        points: Suspicion points for this event.
        label: Category label (e.g. 'Large Paste') or None.
        hmac_sig: HMAC-SHA256 hex signature for this row.
        session_id: Optional session foreign key; resolved automatically if omitted.

    Returns:
        True when the row was inserted, False when skipped as a duplicate.
    """
    dedup_key = f"{event_type}|{detail}"
    now = time.time()
    if dedup_key in _last_event and (now - _last_event[dedup_key]) < DEDUP_SECONDS:
        return False
    _last_event[dedup_key] = now

    # Always attach events to the current open session; NULL if exam has ended
    if session_id is None:
        session_id = get_open_session_id()

    insert_sql = """
        INSERT INTO activity_logs
            (timestamp, event_type, detail, flagged, points, label, hmac_sig, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    with _db_lock:
        connection = _get_connection()
        try:
            connection.execute(
                insert_sql,
                (
                    timestamp,
                    event_type,
                    detail,
                    flagged,
                    points,
                    label,
                    hmac_sig,
                    session_id,
                ),
            )
            connection.commit()
            return True
        finally:
            connection.close()


def _rows_to_dicts(rows: list) -> list[dict]:
    """
    Convert sqlite3.Row objects to plain Python dicts.

    Args:
        rows: List of sqlite3.Row objects.

    Returns:
        List of dicts with column names as keys.
    """
    return [dict(row) for row in rows]


def get_all_events(session_id: int | None = None) -> list[dict]:
    """
    Fetch activity log rows ordered by timestamp ascending.

    Args:
        session_id: When set, restrict results to one exam session.

    Returns:
        List of event dicts.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            if session_id is None:
                cursor = connection.execute(
                    "SELECT * FROM activity_logs ORDER BY timestamp ASC"
                )
            else:
                cursor = connection.execute(
                    "SELECT * FROM activity_logs WHERE session_id = ? ORDER BY timestamp ASC",
                    (session_id,),
                )
            return _rows_to_dicts(cursor.fetchall())
        finally:
            connection.close()


def get_flagged_events(session_id: int | None = None) -> list[dict]:
    """
    Fetch only flagged activity log rows.

    Args:
        session_id: When set, restrict results to one exam session.

    Returns:
        List of flagged event dicts.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            if session_id is None:
                cursor = connection.execute(
                    "SELECT * FROM activity_logs WHERE flagged = 1 ORDER BY timestamp ASC"
                )
            else:
                cursor = connection.execute(
                    """
                    SELECT * FROM activity_logs
                    WHERE flagged = 1 AND session_id = ?
                    ORDER BY timestamp ASC
                    """,
                    (session_id,),
                )
            return _rows_to_dicts(cursor.fetchall())
        finally:
            connection.close()


def get_total_score(session_id: int | None = None) -> int:
    """
    Sum suspicion points across activity log rows.

    Args:
        session_id: When set, restrict the sum to one exam session.

    Returns:
        Total points as integer.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            if session_id is None:
                cursor = connection.execute(
                    "SELECT COALESCE(SUM(points), 0) AS total FROM activity_logs"
                )
            else:
                cursor = connection.execute(
                    "SELECT COALESCE(SUM(points), 0) AS total FROM activity_logs WHERE session_id = ?",
                    (session_id,),
                )
            row = cursor.fetchone()
            return int(row["total"])
        finally:
            connection.close()


def create_session(
    question: str,
    student_name: str,
    session_name: str = "Exam Session",
) -> int:
    """
    Insert a new exam session row with current ISO8601 started_at.

    Args:
        question: Exam question text.
        student_name: Student name (may be empty string).
        session_name: Display name for the session sidebar.

    Returns:
        Primary key id of the newly created session.
    """
    started_at = datetime.now().isoformat()
    insert_sql = """
        INSERT INTO exam_session (question, started_at, student_name, session_name)
        VALUES (?, ?, ?, ?)
    """
    with _db_lock:
        connection = _get_connection()
        try:
            cursor = connection.execute(
                insert_sql,
                (question, started_at, student_name, session_name),
            )
            connection.commit()
            return int(cursor.lastrowid)
        finally:
            connection.close()


def end_all_open_sessions() -> None:
    """
    Set ended_at on every exam session that is still open.

    Called before starting a new dashboard session so events attach cleanly.
    """
    ended_at = datetime.now().isoformat()
    with _db_lock:
        connection = _get_connection()
        try:
            connection.execute(
                "UPDATE exam_session SET ended_at = ? WHERE ended_at IS NULL",
                (ended_at,),
            )
            connection.commit()
        finally:
            connection.close()


def end_session(session_id: int | None = None) -> None:
    """
    Set ended_at on an exam session.

    Args:
        session_id: Specific session to close; defaults to latest open session.
    """
    ended_at = datetime.now().isoformat()
    with _db_lock:
        connection = _get_connection()
        try:
            if session_id is not None:
                connection.execute(
                    "UPDATE exam_session SET ended_at = ? WHERE id = ?",
                    (ended_at, session_id),
                )
            else:
                connection.execute(
                    """
                    UPDATE exam_session
                    SET ended_at = ?
                    WHERE id = (
                        SELECT id FROM exam_session
                        WHERE ended_at IS NULL
                        ORDER BY id DESC
                        LIMIT 1
                    )
                    """,
                    (ended_at,),
                )
            connection.commit()
        finally:
            connection.close()


def delete_session(session_id: int) -> bool:
    """
    Delete an exam session and all its associated activity logs.

    Args:
        session_id: Session primary key to delete.

    Returns:
        True when a row was deleted.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            connection.execute("DELETE FROM activity_logs WHERE session_id = ?", (session_id,))
            cursor = connection.execute("DELETE FROM exam_session WHERE id = ?", (session_id,))
            connection.commit()
            return cursor.rowcount > 0
        finally:
            connection.close()


def get_current_session() -> dict | None:
    """
    Return the latest exam session row as a dict, or None if no sessions exist.

    Returns:
        Session dict or None.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            cursor = connection.execute(
                "SELECT * FROM exam_session ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            connection.close()


def get_session_by_id(session_id: int) -> dict | None:
    """
    Fetch a single exam session by primary key.

    Args:
        session_id: Session id to load.

    Returns:
        Session dict or None when not found.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            cursor = connection.execute(
                "SELECT * FROM exam_session WHERE id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            connection.close()


def get_all_sessions() -> list[dict]:
    """
    List all exam sessions with aggregate score and flagged counts.

    Returns:
        List of session summary dicts ordered newest first.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            cursor = connection.execute(
                """
                SELECT
                    s.id,
                    s.session_name,
                    s.question,
                    s.student_name,
                    s.started_at,
                    s.ended_at,
                    COALESCE(SUM(l.points), 0) AS total_score,
                    COALESCE(SUM(CASE WHEN l.flagged = 1 THEN 1 ELSE 0 END), 0) AS flagged_count
                FROM exam_session s
                LEFT JOIN activity_logs l ON l.session_id = s.id
                GROUP BY s.id
                ORDER BY s.id DESC
                """
            )
            sessions = []
            for row in cursor.fetchall():
                session_dict = dict(row)
                started = _parse_iso(session_dict.get("started_at"))
                ended = _parse_iso(session_dict.get("ended_at"))
                if started:
                    end_dt = ended or datetime.now()
                    duration_minutes = round(
                        max(0.0, (end_dt - started).total_seconds()) / 60.0,
                        1,
                    )
                else:
                    duration_minutes = 0.0
                session_dict["duration_minutes"] = duration_minutes
                session_dict["total_score"] = int(session_dict["total_score"])
                session_dict["flagged_count"] = int(session_dict["flagged_count"])
                sessions.append(session_dict)
            return sessions
        finally:
            connection.close()


def _parse_iso(timestamp_text: str | None) -> datetime | None:
    """
    Parse an ISO8601 timestamp string safely.

    Args:
        timestamp_text: ISO string from SQLite.

    Returns:
        Parsed datetime or None.
    """
    if not timestamp_text:
        return None
    try:
        return datetime.fromisoformat(timestamp_text)
    except (ValueError, TypeError):
        return None


def rename_session(session_id: int, new_name: str) -> bool:
    """
    Update the display name of an exam session.

    Args:
        session_id: Session primary key.
        new_name: New sidebar label.

    Returns:
        True when a row was updated.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            cursor = connection.execute(
                "UPDATE exam_session SET session_name = ? WHERE id = ?",
                (new_name.strip(), session_id),
            )
            connection.commit()
            return cursor.rowcount > 0
        finally:
            connection.close()


def get_session_events(session_id: int) -> list[dict]:
    """
    Fetch all activity log rows belonging to one exam session.

    Args:
        session_id: Session primary key.

    Returns:
        Chronologically ordered event dicts.
    """
    return get_all_events(session_id=session_id)


def get_session_score(session_id: int) -> int:
    """
    Sum suspicion points for a single exam session.

    Args:
        session_id: Session primary key.

    Returns:
        Total points for that session.
    """
    return get_total_score(session_id=session_id)


def reset_labeled_scores(session_id: int | None = None) -> None:
    """
    Clear points, flagged, and label on rows that were previously scored.

    Args:
        session_id: When set, only reset rows for that session.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            if session_id is None:
                connection.execute(
                    """
                    UPDATE activity_logs
                    SET points = 0, flagged = 0, label = NULL
                    WHERE label IS NOT NULL
                    """
                )
            else:
                connection.execute(
                    """
                    UPDATE activity_logs
                    SET points = 0, flagged = 0, label = NULL
                    WHERE label IS NOT NULL AND session_id = ?
                    """,
                    (session_id,),
                )
            connection.commit()
        finally:
            connection.close()


def get_score_breakdown(session_id: int | None = None) -> list[dict]:
    """
    Aggregate suspicion points grouped by rule label for the breakdown card.

    Args:
        session_id: When set, restrict aggregation to one session.

    Returns:
        List of {label, total} dicts ordered by total points descending.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            if session_id is None:
                cursor = connection.execute(
                    """
                    SELECT label, SUM(points) AS total
                    FROM activity_logs
                    WHERE flagged = 1 AND label IS NOT NULL
                    GROUP BY label
                    ORDER BY total DESC
                    """
                )
            else:
                cursor = connection.execute(
                    """
                    SELECT label, SUM(points) AS total
                    FROM activity_logs
                    WHERE flagged = 1 AND label IS NOT NULL AND session_id = ?
                    GROUP BY label
                    ORDER BY total DESC
                    """,
                    (session_id,),
                )
            return [
                {"label": row["label"], "total": int(row["total"])}
                for row in cursor.fetchall()
            ]
        finally:
            connection.close()


def get_recent_events(limit: int = 100, session_id: int | None = None) -> list[dict]:
    """
    Fetch the most recent activity log rows for the timeline API.

    Args:
        limit: Maximum number of rows to return (default 100).
        session_id: When set, restrict results to one exam session.

    Returns:
        List of event dicts ordered newest first.
    """
    with _db_lock:
        connection = _get_connection()
        try:
            if session_id is None:
                cursor = connection.execute(
                    """
                    SELECT * FROM activity_logs
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            else:
                cursor = connection.execute(
                    """
                    SELECT * FROM activity_logs
                    WHERE session_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (session_id, limit),
                )
            return _rows_to_dicts(cursor.fetchall())
        finally:
            connection.close()


def update_event_score(event_id: int, points: int, label: str) -> None:
    """
    Update suspicion points and label on an activity log row (thread-safe).

    Args:
        event_id: Primary key of the activity_logs row.
        points: Suspicion points to assign.
        label: Rule label (e.g. 'AI Tool', 'Search Engine').
    """
    update_sql = """
        UPDATE activity_logs
        SET flagged = 1, points = ?, label = ?
        WHERE id = ?
    """
    with _db_lock:
        connection = _get_connection()
        try:
            connection.execute(update_sql, (points, label, event_id))
            connection.commit()
        finally:
            connection.close()


def batch_update_event_scores(updates: list[tuple[int, int, str]]) -> None:
    """
    Apply many score updates in a single transaction for performance.

    Args:
        updates: List of (event_id, points, label) tuples.
    """
    if not updates:
        return
    update_sql = """
        UPDATE activity_logs
        SET flagged = 1, points = ?, label = ?
        WHERE id = ?
    """
    sql_rows = [(points, label, event_id) for event_id, points, label in updates]
    with _db_lock:
        connection = _get_connection()
        try:
            connection.executemany(update_sql, sql_rows)
            connection.commit()
        finally:
            connection.close()
