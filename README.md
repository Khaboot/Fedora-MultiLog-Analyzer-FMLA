# Fedora MultiLog Analyzer [FMLA]

A Python learning project focused on parsing Fedora authentication logs and building a simple security monitoring tool.

This project was built as part of my Python learning path (FreeCodeCamp + self-practice) and is intended to demonstrate practical understanding of:

- file handling
- string parsing
- dictionaries and counting patterns
- basic threat detection logic
- object-oriented programming (OOP)

## Purpose

The goal is not to replicate a production SIEM system, but to:

- understand how Linux logs look and behave
- practice building detection rules
- learn how attackers patterns (brute-force, scanning) appear in logs
- improve Python structuring using classes and methods

## Features

- Parses Fedora authentication logs:
  - `/var/log/secure` 
  - `/var/log/boot.log` 
  - `/var/log/messages`
  - `/var/log/dnf.log`
  - custom log path

- Detects security-related events:
  - Failed SSH login attempts
  - Invalid user enumeration
  - sudo usage patterns
  - root login attempts

- Extracts and tracks:
  - IP-based activity frequency
  - usernames (when available in logs)
  - hourly activity distribution

- Generates alerts for:
  - brute-force patterns (repeated failed logins)
  - scanning / enumeration behavior

- Produces a structured report including:
  - summary statistics
  - top IP addresses
  - detected alerts
  - raw event logs (for transparency)

- Optional report export to `.txt`

## Why this project exists

This project is part of my learning process in Python and cybersecurity fundamentals.

Instead of only solving isolated exercises, I wanted to:
- simulate a real-world SOC-style task
- build something structured using classes and methods
- understand how log-based detection logic is designed

## Requirements

- Python 3.10+
## How to run

```bash
python log_analyzer.py
