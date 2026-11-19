#!/usr/bin/env python3
import json
import re
import subprocess
import sys


PROJECT_MODULE = "github.com/d4rkfella/apk-registry"
# The unreviewed Go DB record omits the fixed version stated in the upstream advisory.
KNOWN_UPSTREAM_FIX = {
    "GO-2026-4588": ("chainguard.dev/melange", (0, 43, 4)),
}


def json_events(text):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            return
        event, offset = decoder.raw_decode(text, offset)
        yield event


def version_tuple(version):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", version)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def has_project_trace(finding):
    return any(
        frame.get("module") == PROJECT_MODULE
        for frame in finding.get("trace", [])
    )


def matches_known_upstream_fix(finding):
    exception = KNOWN_UPSTREAM_FIX.get(finding.get("osv"))
    if exception is None:
        return False
    module, minimum_version = exception
    versions = [
        version_tuple(frame["version"])
        for frame in finding.get("trace", [])
        if frame.get("module") == module and frame.get("version")
    ]
    return bool(versions) and all(
        version is not None and version >= minimum_version for version in versions
    )


def main():
    try:
        result = subprocess.run(
            ["govulncheck", "-format=json", "./..."],
            capture_output=True,
            check=False,
            text=True,
        )
    except FileNotFoundError:
        print("govulncheck is not installed or is not in PATH.", file=sys.stderr)
        return 127
    sys.stderr.write(result.stderr)
    if result.returncode not in (0, 3):
        return result.returncode

    events = list(json_events(result.stdout))
    if not any("config" in event for event in events):
        print("govulncheck returned no scan metadata.", file=sys.stderr)
        return 2
    findings = {
        event["finding"]["osv"]: event["finding"]
        for event in events
        if "finding" in event and has_project_trace(event["finding"])
    }
    unreviewed = [
        finding
        for finding in findings.values()
        if not matches_known_upstream_fix(finding)
    ]
    if unreviewed:
        print(
            "Reachable Go vulnerabilities: "
            + ", ".join(sorted(finding["osv"] for finding in unreviewed)),
            file=sys.stderr,
        )
        return 1

    if findings:
        print(
            "govulncheck: GO-2026-4588 is suppressed only for melange versions "
            ">= v0.43.4. The upstream advisory lists v0.43.4 as fixed; the Go "
            "vulnerability database currently marks all versions affected, "
            "although the reported issue is in melange update-cache "
            "(https://github.com/chainguard-dev/melange/security/advisories/"
            "GHSA-7rp8-r62p-q6wc)."
        )
    else:
        print("govulncheck: no reachable vulnerabilities found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
