class SecurityReporter:

    def show(self, alerts):
        print("=" * 60)
        print("       SECURITY LOG ANALYZER REPORT")
        print("=" * 60)

        if not alerts:
            print("\nNo suspicious activity detected.")
            return

        print(f"\nTotal Alerts: {len(alerts)}")
        print("-" * 60)

        for number, alert in enumerate(alerts, start=1):

            print(f"\nAlert #{number}")
            print(f"Rule     : {alert.rule_name}")
            print(f"Severity : {alert.severity}")
            print(f"Message  : {alert.message}")

            if alert.username:
                print(f"User     : {alert.username}")

            if alert.ip_address:
                print(f"IP       : {alert.ip_address}")

            if alert.timestamp:
                print(f"Time     : {alert.timestamp}")

            print("-" * 60)