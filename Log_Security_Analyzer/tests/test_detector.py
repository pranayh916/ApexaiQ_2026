from datetime import datetime

from app.config import SecurityConfig
from app.detector import SecurityDetector
from app.models import LogEntry


def create_log(time, user, ip, status, location):
    return LogEntry(
        timestamp=datetime.strptime(time, "%Y-%m-%d %H:%M:%S"),
        username=user,
        ip_address=ip,
        status=status,
        location=location
    )


def get_detector():
    config = SecurityConfig("config/rules.json")
    return SecurityDetector(config)


def test_multiple_failed_logins():
    detector = get_detector()

    logs = [
        create_log("2026-08-30 10:00:00", "Rahul", "10.0.0.1", "FAILED", "Mumbai-IN"),
        create_log("2026-08-30 10:01:00", "Rahul", "10.0.0.1", "FAILED", "Mumbai-IN"),
        create_log("2026-08-30 10:02:00", "Rahul", "10.0.0.1", "FAILED", "Mumbai-IN"),
        create_log("2026-08-30 10:03:00", "Rahul", "10.0.0.1", "FAILED", "Mumbai-IN"),
        create_log("2026-08-30 10:04:00", "Rahul", "10.0.0.1", "FAILED", "Mumbai-IN")
    ]

    alerts = detector.check_failed_logins(logs)

    assert len(alerts) == 1
    assert alerts[0].username == "Rahul"


def test_brute_force():
    detector = get_detector()

    logs = []

    for i in range(8):
        logs.append(
            create_log(
                f"2026-08-30 11:00:{i:02d}",
                f"User{i}",
                "203.0.113.9",
                "FAILED",
                "Unknown"
            )
        )

    alerts = detector.check_brute_force(logs)

    assert len(alerts) == 1
    assert alerts[0].ip_address == "203.0.113.9"


def test_multiple_users_from_ip():
    detector = get_detector()

    logs = [
        create_log("2026-08-30 12:00:00", "Rahul", "203.0.113.9", "FAILED", "Unknown"),
        create_log("2026-08-30 12:01:00", "Amit", "203.0.113.9", "FAILED", "Unknown"),
        create_log("2026-08-30 12:02:00", "Priya", "203.0.113.9", "FAILED", "Unknown"),
        create_log("2026-08-30 12:03:00", "Neha", "203.0.113.9", "FAILED", "Unknown"),
        create_log("2026-08-30 12:04:00", "Admin", "203.0.113.9", "FAILED", "Unknown")
    ]

    alerts = detector.check_multiple_users(logs)

    assert len(alerts) == 1
    assert alerts[0].ip_address == "203.0.113.9"


def test_unusual_login_source():
    detector = get_detector()

    logs = [
        create_log(
            "2026-08-30 13:00:00",
            "Amit",
            "91.108.56.12",
            "SUCCESS",
            "Moscow-RU"
        )
    ]

    alerts = detector.check_unusual_source(logs)

    assert len(alerts) == 1
    assert alerts[0].username == "Amit"


def test_success_after_failures():
    detector = get_detector()

    logs = [
        create_log("2026-08-30 14:00:00", "Rahul", "10.0.0.5", "FAILED", "Unknown"),
        create_log("2026-08-30 14:01:00", "Rahul", "10.0.0.5", "FAILED", "Unknown"),
        create_log("2026-08-30 14:02:00", "Rahul", "10.0.0.5", "FAILED", "Unknown"),
        create_log("2026-08-30 14:03:00", "Rahul", "10.0.0.5", "SUCCESS", "Mumbai-IN")
    ]

    alerts = detector.check_success_after_failures(logs)

    assert len(alerts) == 1
    assert alerts[0].username == "Rahul"