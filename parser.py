"""
Parses a requirements.txt into a list of (name, version) pairs this tool
can actually look up - skipping anything it can't resolve to an exact
version (unpinned requirements, VCS/URL installs, local paths, extras)
rather than guessing.
"""

import re

PINNED_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*?)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+-]+)\s*$"
)


def parse_requirements(path_or_lines):
    """Accepts a file path or an iterable of lines. Returns
    (resolved, skipped) - resolved is a list of (name, version) tuples;
    skipped is a list of (raw_line, reason) for anything not handled."""
    if isinstance(path_or_lines, str):
        with open(path_or_lines) as f:
            lines = f.readlines()
    else:
        lines = path_or_lines

    resolved = []
    skipped = []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            skipped.append((line, "option/flag line, not a package"))
            continue
        # Strip inline comments and environment markers (after ';')
        line_no_comment = line.split("#", 1)[0].strip()
        line_no_marker = line_no_comment.split(";", 1)[0].strip()

        if "://" in line_no_marker or line_no_marker.startswith("git+"):
            skipped.append((line, "VCS/URL install - no fixed version to look up"))
            continue

        match = PINNED_RE.match(line_no_marker)
        if not match:
            skipped.append((line, "not pinned to an exact version (==) - can't look up a range"))
            continue

        name, version = match.group(1), match.group(2)
        resolved.append((normalize_name(name), version))

    return resolved, skipped


def normalize_name(name):
    """PyPI package name normalization (PEP 503): lowercase, runs of
    -_. collapsed to a single '-'. OSV's PyPI ecosystem expects this."""
    return re.sub(r"[-_.]+", "-", name).lower()
