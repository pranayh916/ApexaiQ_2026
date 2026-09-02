from .parser import LogParser
from .detector import SecurityDetector


class SecurityAnalyzer:

    def __init__(self, config):
        self.parser = LogParser()
        self.detector = SecurityDetector(config)

    def analyze_file(self, file_path):
        logs = self.parser.parse_file(file_path)
        alerts = self.detector.detect(logs)

        return alerts