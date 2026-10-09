#!/usr/bin/env python3
"""Reject credential-bearing evidence; redact known log formats before publication."""
import argparse
from pathlib import Path
import re


SENSITIVE = re.compile(
    r"Using generated security password:\s*\S+"
    r"|field '(?:password|refresh_token)': rejected value \["
    r"|(?i:(?<!\w)Authorization[\"']?\s*[:=])"
    r"|(?i:(?<!\w)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token)[\"']?\s*[:=])"
    r"|-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----"
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----.*?(?:-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----|\Z)", re.DOTALL)
SUMMARY = re.compile(
    r"^\[(?:INFO|ERROR)\] (?:BUILD (?:SUCCESS|FAILURE)"
    r"|Tests run: [0-9]+, Failures: [0-9]+(?:, Errors: [0-9]+, Skipped: [0-9]+)?"
    r"(?:, Time elapsed: [0-9.]+ s(?: <<< (?:FAILURE|ERROR)!)? -- in com\.augustopugliano\.cypher\.[A-Za-z0-9_]+)?)$"
)


def summary(text):
    return "".join(line + "\n" for line in text.splitlines() if SUMMARY.fullmatch(line.strip()))


def redact(text):
    text = PRIVATE_KEY.sub("[REDACTED private key]", text)
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if SENSITIVE.search(line):
            # Unknown log delimiters cannot safely bound a multiline credential.
            return "".join(lines[:index]) + "[REDACTED credential-bearing log remainder]\n" + summary("".join(lines[index:]))
    return text


def findings(text):
    return [number for number, line in enumerate(text.splitlines(), 1) if SENSITIVE.search(line)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--redact", action="store_true", help="Sanitize explicitly selected log files in place")
    mode.add_argument("--summary", action="store_true", help="Print only strictly formatted Maven test/build summaries")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    files = []
    for path in args.paths:
        if args.redact and path.is_dir():
            parser.error("--redact requires explicit log files, not directories")
        if not path.exists():
            parser.error(f"Missing evidence path: {path}")
        if path.is_dir():
            files.extend(p for p in path.rglob("*") if p.is_file())
        else:
            files.append(path)
    rejected = False
    for path in sorted(files):
        text = path.read_text()
        if args.redact:
            path.write_text(redact(text))
        elif args.summary:
            print(summary(text), end="")
        else:
            for number in findings(text):
                print(f"{path}:{number}: credential-bearing evidence rejected (value withheld)")
                rejected = True
    return int(rejected)


if __name__ == "__main__":
    raise SystemExit(main())
