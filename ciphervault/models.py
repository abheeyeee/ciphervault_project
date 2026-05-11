from dataclasses import dataclass, asdict
from datetime import datetime, UTC
from typing import Optional

@dataclass
class Entry:
    name: str
    username: str
    password: str
    notes: Optional[str]
    created_at: str

    @staticmethod
    def create(name: str, username: str, password: str, notes: Optional[str] = None):
        return Entry(
            name=name,
            username=username,
            password=password,
            notes=notes or "",
            created_at=datetime.now(UTC).isoformat()   # FIXED
        )

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d: dict):
        return Entry(
            name=d["name"],
            username=d["username"],
            password=d["password"],
            notes=d.get("notes", ""),
            created_at=d.get("created_at", datetime.now(UTC).isoformat())  # already correct
        )
