from collections import defaultdict
from datetime import timedelta

from .models import Alert


class SecurityDetector:

    def __init__(self, config):
        self.config = config

    def _get_logs_in_window(self, logs, start_time, minutes):
        window = timedelta(minutes=minutes)

        return [
            log
            for log in logs
            if log.timestamp - start_time <= window
        ]

    def detect(self, logs):
        alerts = []

        alerts += self.check_failed_logins(logs)
        alerts += self.check_brute_force(logs)
        alerts += self.check_multiple_users(logs)
        alerts += self.check_unusual_source(logs)
        alerts += self.check_success_after_failures(logs)

        return alerts

    # ---------------------------------------------------------
    # 1. Multiple failed logins
    # ---------------------------------------------------------

    def check_failed_logins(self, logs):
        alerts = []
        rule = self.config.get_rule("multiple_failed_logins")

        if not rule["enabled"]:
            return alerts

        failed_by_user = defaultdict(list)

        for log in logs:
            if log.status == "FAILED":
                failed_by_user[log.username].append(log)

        for username, user_logs in failed_by_user.items():

            for log in user_logs:

                window_logs = self._get_logs_in_window(
                    user_logs,
                    log.timestamp,
                    rule["window_minutes"]
                )

                if len(window_logs) >= rule["threshold"]:

                    alerts.append(
                        Alert(
                            timestamp=log.timestamp,
                            rule_name="multiple_failed_logins",
                            severity=rule["severity"],
                            message=(
                                f"{len(window_logs)} failed logins "
                                f"for {username}"
                            ),
                            username=username,
                            ip_address=log.ip_address
                        )
                    )

                    break

        return alerts

    # ---------------------------------------------------------
    # 2. Brute-force attack
    # ---------------------------------------------------------

    def check_brute_force(self, logs):
        alerts = []
        rule = self.config.get_rule("brute_force")

        if not rule["enabled"]:
            return alerts

        failed_by_ip = defaultdict(list)

        for log in logs:
            if log.status == "FAILED":
                failed_by_ip[log.ip_address].append(log)

        for ip, ip_logs in failed_by_ip.items():

            for log in ip_logs:

                window_logs = self._get_logs_in_window(
                    ip_logs,
                    log.timestamp,
                    rule["window_minutes"]
                )

                if len(window_logs) >= rule["threshold"]:

                    alerts.append(
                        Alert(
                            timestamp=log.timestamp,
                            rule_name="brute_force",
                            severity=rule["severity"],
                            message=f"Brute-force attempt from {ip}",
                            ip_address=ip
                        )
                    )

                    break

        return alerts

    # ---------------------------------------------------------
    # 3. Multiple users from one IP
    # ---------------------------------------------------------

    def check_multiple_users(self, logs):
        alerts = []
        rule = self.config.get_rule("multiple_users_per_ip")

        if not rule["enabled"]:
            return alerts

        logs_by_ip = defaultdict(list)

        for log in logs:
            if log.status == "FAILED":
                logs_by_ip[log.ip_address].append(log)

        for ip, ip_logs in logs_by_ip.items():

            for log in ip_logs:

                window_logs = self._get_logs_in_window(
                    ip_logs,
                    log.timestamp,
                    rule["window_minutes"]
                )

                users = {
                    entry.username
                    for entry in window_logs
                }

                if len(users) >= rule["threshold"]:

                    alerts.append(
                        Alert(
                            timestamp=log.timestamp,
                            rule_name="multiple_users_per_ip",
                            severity=rule["severity"],
                            message=(
                                f"{len(users)} users attacked "
                                f"from IP {ip}"
                            ),
                            ip_address=ip
                        )
                    )

                    break

        return alerts

    # ---------------------------------------------------------
    # 4. Unusual login source
    # ---------------------------------------------------------

    def check_unusual_source(self, logs):
        alerts = []
        rule = self.config.get_rule("unusual_login_source")

        if not rule["enabled"]:
            return alerts

        for log in logs:

            # Check location only for successful logins
            if log.status != "SUCCESS":
                continue

            trusted = self.config.get_trusted_locations(
                log.username
            )

            if trusted and log.location not in trusted:

                alerts.append(
                    Alert(
                        timestamp=log.timestamp,
                        rule_name="unusual_login_source",
                        severity=rule["severity"],
                        message=f"Unusual location: {log.location}",
                        username=log.username,
                        ip_address=log.ip_address
                    )
                )

        return alerts

    # ---------------------------------------------------------
    # 5. Successful login after repeated failures
    # ---------------------------------------------------------

    def check_success_after_failures(self, logs):
        alerts = []
        rule = self.config.get_rule("success_after_failures")

        if not rule["enabled"]:
            return alerts

        user_logs = defaultdict(list)

        for log in logs:
            user_logs[log.username].append(log)

        for username, entries in user_logs.items():

            for index, log in enumerate(entries):

                if log.status != "SUCCESS":
                    continue

                previous_logs = entries[:index]

                failed_logs = []

                for previous in reversed(previous_logs):

                    if (
                        log.timestamp - previous.timestamp
                        > timedelta(minutes=rule["window_minutes"])
                    ):
                        break

                    if previous.status == "FAILED":
                        failed_logs.append(previous)
                    else:
                        break

                if len(failed_logs) >= rule["threshold"]:

                    alerts.append(
                        Alert(
                            timestamp=log.timestamp,
                            rule_name="success_after_failures",
                            severity=rule["severity"],
                            message=(
                                f"Successful login after "
                                f"{len(failed_logs)} failures"
                            ),
                            username=username,
                            ip_address=log.ip_address
                        )
                    )

        return alerts