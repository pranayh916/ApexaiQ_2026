from datetime import datetime
from typing import List

from .models import LogEntry


class LogParser:

    def parse_line(self, line: str) -> LogEntry | None:
        line = line.strip()

        # Ignore empty lines and comments
        if not line or line.startswith("#"):
            return None

        # Split the log line into 5 parts
        parts = [part.strip() for part in line.split(",")]

        # Check the log format
        if len(parts) != 5:
            return None

        timestamp_text = parts[0]
        username = parts[1]
        ip_address = parts[2]
        status = parts[3].upper()
        location = parts[4]

        # Convert text timestamp into datetime
        timestamp = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        )

        # Validate login status
        if status not in ("SUCCESS", "FAILED"):
            return None

        return LogEntry(
            timestamp=timestamp,
            username=username,
            ip_address=ip_address,
            status=status,
            location=location
        )

    def parse_file(self, file_path: str) -> List[LogEntry]:
        entries = []

        with open(file_path, "r", encoding="utf-8") as file:

            for line in file:
                entry = self.parse_line(line)

                if entry is not None:
                    entries.append(entry)

        return entries