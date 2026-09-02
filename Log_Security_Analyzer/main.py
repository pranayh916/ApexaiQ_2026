from app.config import SecurityConfig
from app.analyzer import SecurityAnalyzer
from app.reporter import SecurityReporter


def main():
    config = SecurityConfig("config/rules.json")

    analyzer = SecurityAnalyzer(config)

    file_path = input("Enter log file path: ")

    alerts = analyzer.analyze_file(file_path)

    reporter = SecurityReporter()
    reporter.show(alerts)


if __name__ == "__main__":
    main()