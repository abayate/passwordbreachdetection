# 🔐 Password Breach Detection

A Python command-line tool that checks whether a password has been exposed in a data breach.

It started as a script for the **2015 Ashley Madison breach**: it hashed a password with MD5 and compared it
against a list of leaked passwords. It now also checks the **Have I Been Pwned** database of 900M+ leaked
passwords in a way that never sends your password anywhere.

## How it works

### Online mode (default): k-anonymity
```
password ──SHA-1──▶ 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
                    └─┬─┘└──────────────┬──────────────────┘
          sent to HIBP API         kept on your machine
                      │
     HIBP returns every hash suffix that starts with "5BAA6"
                      │
     the script looks for your suffix locally ──▶ found / not found
```
The API only ever sees the first 5 characters of the hash, which match hundreds of unrelated passwords.
This is the same technique password managers and browsers use.

### Offline mode: local wordlist
Pass `--wordlist` with a file of leaked passwords (one per line, such as the cracked Ashley Madison list). The
script MD5-hashes your input and every entry, then compares them.

## Usage

```bash
python passwordbreachdetection.py                         # check against Have I Been Pwned
python passwordbreachdetection.py --wordlist leaked.txt   # check against a local list
```

```
Enter a password to check:          (typed "password")
⚠️  This password has appeared in breaches 52,372,427 times. Do not use it.
```

The password is typed with `getpass`, so it is never echoed to the screen or saved in shell history.
No third-party packages are needed (Python 3.8+ standard library only).

## Why this matters

- **Unsalted MD5 is broken for passwords.** The same password always gives the same hash, and modern GPUs
  compute billions of MD5 hashes per second. This is why Ashley Madison's MD5-hashed login tokens let
  researchers crack 11M+ passwords, even though the main password field used bcrypt.
- **Credential stuffing** (trying leaked passwords on other sites) is one of the most common account takeover
  techniques ([MITRE ATT&CK T1110.004](https://attack.mitre.org/techniques/T1110/004/)). Checking passwords
  against breach corpora is recommended by [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).

## Skills demonstrated

Python · cryptographic hashing (MD5, SHA-1) · k-anonymity · REST APIs · secure input handling
