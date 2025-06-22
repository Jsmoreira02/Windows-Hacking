<img src="../Images/Pyenum.png">


# PyEnum - Windows Privilege Escalation Enumeration Script

## Introduction

**PyEnum** is a Python script that helps you quickly spot possible ways to escalate privileges on a Windows machine. It's inspired by tools like PEASS-ng and guides like HackTricks. The goal is to find common misconfigurations, weak permissions, and sensitive data that could be exploited.

Use it only for learning or on systems you’re allowed to test.
flaws, and potentially sensitive data across a Windows host.

It is intended for **educational and authorized penetration testing purposes only**.

## Content Index

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [How It Works](#how-it-works)
- [Usage](#usage)
- [Dependencies](#dependencies)
- [Examples](#Examples)
- [Troubleshooting](#troubleshooting)
- [Contributors](#contributors)
- [License](#license)

## Features

- Scans for misconfigurations that could let someone escalate privileges
- Searches for credentials and secrets buried in files
- Lets you filter by file type
- Uses colors to make results easier to read
- Built to be modular, so you can add your own stuff

## Installation

No installation is required. Simply download and run the script on a PowerShell-compatible Windows system.

```python
git clone https://your-repo-url
cd your-repo
python3 PyEnum.py
```

or

```python
git clone https://your-repo-url
cd your-repo
make
.\PyEnum.exe
```

## Usage

```python
# Run a basic scan
python3 PyEnum.py

# Look for saved passwords or usernames
python3 PyEnum.py --credentials

# Search specific file types
python3 PyEnum.py --credentials --extensions ".txt,.xml"

# Just search for certain file extensions
python3 PyEnum.py --search --extensions ".docx,.ini"

# Need help?
python3 PyEnum.py --help
```

## How It Works

The script checks a few common ways attackers try to escalate privileges:

### 🔹 Filesystem and Drive Scanning

- Checking Files and Drives
- Looks for files that might have passwords or secrets using keywords.
- Scans for extensions like `.txt`, `.xml`, `.config`
- Tries to spot things like:
  - `password`, `secret`, `token`, `api_key`, `username`
  - Regex-based matching to identify hardcoded credentials and tokens.

### 🔹 Registry and Service Misconfigurations

- Detects possible misconfigurations that may be exploited by attackers, such as:
  - Weak registry permissions
  - Services with unquoted paths
  - Auto-run registry keys

### 🔹 Local User and Group Enumeration

- Checks current user privileges
- Looks for users in admin groups they probably shouldn’t be in

### 🔹 Script Injection and Auto-Elevated Binaries

- Highlights potentially injectable paths
- Looks for binaries or scripts run by higher-privilege users

## Dependencies

- Python3 or superior installed
- Administrator privileges enhance discovery but are not required for basic enumeration
- You can compile with pyinstaller and run an .exe

## Examples

```python
# Search for credentials in .ini and .conf files
python3 PyEnum.py --credentials --extensions ".ini,.conf"
```

```python
# Just search for all .txt and .docx files
python3 PyEnum.py --search --extensions ".txt,.docx"
```

## Troubleshooting

  - **False Positives:** The script looks for patterns, so some results might need a second look.
  - **Permission Problems:** Some files or areas might need admin rights to access.

## Contributors

This tool was made by someone passionate about cybersecurity, to help others learn how to do Windows enumeration and ethical hacking.

Credits and thanks to:
- [PEASS-ng](https://github.com/peass-ng)
- [HackTricks](https://book.hacktricks.wiki)

## License

This is made for **educational and authorized security assessment purposes only**. Misuse of this script is strictly discouraged. This entire repo is for learning and legal security testing only. Don’t use it for anything shady.
