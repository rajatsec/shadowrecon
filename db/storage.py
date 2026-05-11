import json
import logging
import time
from typing import Any, Dict, List

import aiosqlite

from .models import ScanRecord

logger = logging.getLogger("ShadowRecon")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    target    TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    data      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (target);
"""


class ScanDB:
    def __init__(self, db_path: str = "shadowrecon.db"):
        self.db_path = db_path

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(_SCHEMA)
            await db.commit()

    async def save_scan(self, record: ScanRecord) -> int:
        data = json.dumps({
            "dns": record.dns,
            "subdomains": record.subdomains,
            "per_provider": record.per_provider,
            "http": record.http,
            "open_ports": {str(k): v for k, v in record.open_ports.items()},
            "takeovers": record.takeovers,
        })
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "INSERT INTO scans (target, timestamp, data) VALUES (?, ?, ?)",
                (record.target, record.timestamp, data),
            )
            await db.commit()
            return cursor.lastrowid

    async def get_scans(self, target: str) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT id, target, timestamp, data FROM scans WHERE target = ? ORDER BY timestamp DESC",
                (target,),
            ) as cursor:
                rows = await cursor.fetchall()
        results = []
        for row in rows:
            entry = {"id": row["id"], "target": row["target"], "timestamp": row["timestamp"]}
            entry.update(json.loads(row["data"]))
            results.append(entry)
        return results

    async def compare_scans(self, id1: int, id2: int) -> Dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT data FROM scans WHERE id = ?", (id1,)) as c:
                row1 = await c.fetchone()
            async with db.execute("SELECT data FROM scans WHERE id = ?", (id2,)) as c:
                row2 = await c.fetchone()

        if not row1 or not row2:
            return {}

        d1 = json.loads(row1["data"])
        d2 = json.loads(row2["data"])

        subs1 = set(d1.get("subdomains", []))
        subs2 = set(d2.get("subdomains", []))
        ports1 = set(d1.get("open_ports", {}).keys())
        ports2 = set(d2.get("open_ports", {}).keys())

        return {
            "new_subdomains": sorted(subs2 - subs1),
            "removed_subdomains": sorted(subs1 - subs2),
            "new_ports": sorted(ports2 - ports1),
            "closed_ports": sorted(ports1 - ports2),
        }
