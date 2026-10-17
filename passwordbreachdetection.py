"""Check whether a password has appeared in a known data breach.

Two modes:
  * online (default): asks the Have I Been Pwned "Pwned Passwords" API using
    k-anonymity. Only the first 5 characters of the password's SHA-1 hash leave
    your machine, never the password itself.
  * --wordlist FILE: compares against a local list of leaked passwords (for
    example, the cracked Ashley Madison list) by MD5 hash, the way the original
    version of this script worked.
"""

import argparse
import getpass
import hashlib
import sys
import urllib.request

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"


def check_hibp(password):
    """Return how many times the password appears in HIBP (0 if never)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    request = urllib.request.Request(
        HIBP_RANGE_URL + prefix,
        headers={"User-Agent": "passwordbreachdetection", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode("utf-8")

    # Each line looks like "SUFFIX:COUNT". Padding rows have a count of 0.
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            return int(count)
    return 0


def check_wordlist(password, wordlist_path):
    """Return True if the password's MD5 hash matches any password in the list."""
    password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:
        for word in wordlist:
            word = word.strip()
            if word and hashlib.md5(word.encode("utf-8")).hexdigest() == password_hash:
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Check if a password has been exposed in a breach.")
    parser.add_argument("--wordlist", help="local file of leaked passwords, one per line (offline mode)")
    args = parser.parse_args()

    # getpass hides the password while you type it, so it never shows on screen.
    password = getpass.getpass("Enter a password to check: ").strip()
    if not password:
        sys.exit("No password entered.")

    if args.wordlist:
        if check_wordlist(password, args.wordlist):
            print("⚠️  FOUND in this breach list. Do not use this password.")
        else:
            print("✅ Not found in this breach list.")
        return

    try:
        count = check_hibp(password)
    except OSError as error:
        sys.exit(f"Could not reach Have I Been Pwned: {error}")

    if count:
        print(f"⚠️  This password has appeared in breaches {count:,} times. Do not use it.")
    else:
        print("✅ This password was not found in any known breach.")


if __name__ == "__main__":
    main()
