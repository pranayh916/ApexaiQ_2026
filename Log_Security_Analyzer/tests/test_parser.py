from app.parser import LogParser


def test_valid_log():
    parser = LogParser()

    line = "2026-08-30 10:00:00, Rahul, 192.168.1.10, SUCCESS, Mumbai-IN"

    result = parser.parse_line(line)

    assert result is not None
    assert result.username == "Rahul"
    assert result.ip_address == "192.168.1.10"
    assert result.status == "SUCCESS"
    assert result.location == "Mumbai-IN"


def test_comment_line():
    parser = LogParser()

    result = parser.parse_line("# This is a comment")

    assert result is None


def test_invalid_log():
    parser = LogParser()

    result = parser.parse_line("invalid log line")

    assert result is None