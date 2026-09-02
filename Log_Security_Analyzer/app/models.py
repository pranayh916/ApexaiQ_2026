from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class LogEntry:
    timestamp: datetime
    username: str
    ip_address: str
    status: str
    location: str


@dataclass
class Alert:
    timestamp: Optional[datetime]
    rule_name: str
    severity: str
    message: str
    username: Optional[str] = None
    ip_address: Optional[str] = None