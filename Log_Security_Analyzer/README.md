# Log Security Analyzer

## Project Overview

Log Security Analyzer is a Python-based security application that analyzes authentication logs and detects suspicious login activities.

The system analyzes login records containing timestamp, username, IP address, login status, and location. It identifies suspicious patterns and generates security alerts when configured conditions are satisfied.

## Problem Statement

The application is designed to detect the following suspicious activities:

1. Multiple failed login attempts
2. Brute-force attempts
3. Multiple users from the same IP address
4. Unusual login sources
5. Successful login after repeated failures

The detection logic is configurable so that security thresholds and time windows can be changed without modifying the source code.

## How It Works

The application first reads the authentication log file and parses each valid log entry.

Each log entry contains:

- Timestamp
- Username
- IP Address
- Status
- Location

The parsed entries are then passed to the security detector.

The detector applies the configured security rules and checks the login activity.

If a suspicious condition is detected, a security alert is generated.

The alert contains information such as:

- Rule name
- Severity
- Username
- IP address
- Timestamp
- Security message

Finally, the generated alerts are displayed as a security report.

## Detection Rules

### 1. Multiple Failed Logins

Detects repeated failed login attempts for the same user within a configured time window.

For example, if a user has five failed login attempts within five minutes, the system can generate an alert.

### 2. Brute-Force Attempts

Detects a large number of failed login attempts from the same IP address within a configured time window.

This can indicate that an attacker is repeatedly trying to access the system.

### 3. Multiple Users From One IP

Detects multiple different users being targeted from the same IP address.

This behavior can indicate credential stuffing or automated account attacks.

### 4. Unusual Login Source

Compares the current login location with the trusted locations configured for the user.

For example, if a user normally logs in from Delhi but suddenly logs in from Moscow, the system generates an unusual login source alert.

### 5. Successful Login After Repeated Failures

Detects a successful login that occurs after multiple consecutive failed attempts.

This can be suspicious because an attacker may have eventually obtained the correct credentials.

## Configuration

The detection rules are stored separately in a JSON configuration file.

The configuration can define:

- Rule status
- Threshold
- Time window
- Severity
- Trusted locations

For example:

```json
{
    "enabled": true,
    "threshold": 5,
    "window_minutes": 5,
    "severity": "HIGH"
}
