#!/usr/bin/env python3
"""
Filter Suricata rules by classification priority and protocol, converting
matching alert rules to drop rules.

The source rule files are never modified. Selected rules are written to one
consolidated output file when --apply is supplied.

Examples:
    python3 convert_severity_to_drop.py \
        --rules-dir ./rules \
        --classification ./classification.config \
        --severity 1 \
        --protocol http

    # Actually write the result (default: <rules-dir-parent>/filtered.rules)
    python3 convert_severity_to_drop.py \
        --rules-dir ./rules \
        --classification ./classification.config \
        --severity 1 \
        --protocol http \
        --apply

    # Replace an existing output file, preserving a timestamped backup
    python3 convert_severity_to_drop.py \
        --rules-dir ./rules \
        --classification ./classification.config \
        --severity 1 \
        --protocol http \
        --apply --force

Notes:
  * --severity and --priority are aliases. Values are Suricata priority
    numbers (for example, 1 or 1,2).
  * A rule's explicit priority: value takes precedence over its classtype.
  * If --severity/--priority is used, rules without a known priority are
    excluded.
  * --protocol http selects rules explicitly identified as HTTP by an
    app-layer-protocol option, an HTTP sticky-buffer/keyword, or an HTTP
    application protocol in the rule header. A generic TCP rule using port
    80 alone is not assumed to be HTTP.
  * This is a practical rule-file filter, not a complete Suricata parser.
    Always validate the generated rules with Suricata -T before deployment.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Rule header and option patterns
# ---------------------------------------------------------------------------

ACTIONS = (
    "alert",
    "drop",
    "pass",
    "reject",
    "rejectsrc",
    "rejectdst",
    "rejectboth",
)

header_re = re.compile(
    r"^\s*(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+(\S+)\s+",
    re.IGNORECASE,
)

PRIORITY_RE = re.compile(
    r"(?:^|;)\s*priority\s*:\s*(\d+)\s*(?:;|$)",
    re.IGNORECASE,
)

CLASSTYPE_RE = re.compile(
    r"(?:^|;)\s*classtype\s*:\s*([A-Za-z0-9_.-]+)\s*(?:;|$)",
    re.IGNORECASE,
)

APP_LAYER_RE = re.compile(
    r"(?:^|;)\s*app-layer-protocol\s*:\s*([A-Za-z0-9_.-]+)\s*(?:;|$)",
    re.IGNORECASE,
)

# HTTP keywords from current and older Suricata rule syntax.
HTTP_LEGACY_KEYWORDS = (
    "uricontent",
    "http_header",
    "http_method",
    "http_uri",
    "http_client_body",
    "http_cookie",
    "http_host",
    "http_stat_code",
    "http_stat_msg",
    "http_user_agent",
    "http_raw_uri",
    "http_raw_header",
)

# Maps app-layer keyword prefixes to application protocols.
APP_KEYWORD_PATTERNS = {
    "http": re.compile(r"\bhttp\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "dns": re.compile(r"\bdns\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "tls": re.compile(r"\btls\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "ssh": re.compile(r"\bssh\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "ftp": re.compile(r"\bftp\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "smtp": re.compile(r"\bsmtp\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "smb": re.compile(r"\bsmb[12]?\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "dcerpc": re.compile(r"\bdcerpc\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "modbus": re.compile(r"\bmodbus\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "dnp3": re.compile(r"\bdnp3\.[A-Za-z0-9_]+\b", re.IGNORECASE),
    "snmp": re.compile(r"\bsnmp\.[A-Za-z0-9_]+\b", re.IGNORECASE),
}


# ---------------------------------------------------------------------------
# Configuration and argument handling
# ---------------------------------------------------------------------------

def parse_priority_list(value: str) -> Set[int]:
    """Parse values such as '1' or '1,2,3' into a set of priorities."""

    priorities: Set[int] = set()

    for item in value.split(","):
        item = item.strip()

        if not item:
            continue

        try:
            number = int(item)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"Invalid priority {item!r}; use numbers such as 1 or 1,2"
            ) from exc

        if number < 1:
            raise argparse.ArgumentTypeError(
                "Priority numbers must be >= 1"
            )

        priorities.add(number)

    if not priorities:
        raise argparse.ArgumentTypeError(
            "At least one priority is required"
        )

    return priorities


def parse_protocol_list(value: str) -> Set[str]:
    protocols = {
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    }

    if not protocols:
        raise argparse.ArgumentTypeError(
            "At least one protocol is required"
        )

    return protocols


def build_argument_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Filter Suricata rules by priority and application/network protocol;                                                                                                                         "
            "convert selected alert rules to drop."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--rules-dir",
        required=True,
        type=Path,
        help="Directory containing source .rules files (searched recursively)",
    )

    parser.add_argument(
        "--classification",
        type=Path,
        default=None,
        help="Suricata classification.config used to map classtype to priority",
    )

    parser.add_argument(
        "--severity",
        "--priority",
        dest="priorities",
        type=parse_priority_list,
        default=None,
        help="Priority number(s) to retain, e.g. 1 or 1,2 (aliases: --priority)"                                                                                                                        ,
    )

    parser.add_argument(
        "--protocol",
        type=parse_protocol_list,
        default=None,
        help="Protocol(s) to retain, e.g. http or http,dns; omit to keep all",
    )

    parser.add_argument(
        "--output-file",
        type=Path,
        default=None,
        help="Output .rules file (default: filtered.rules beside the rules direc                                                                                                                        tory)",
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the filtered rules to the output file; without this, report                                                                                                                         only",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow replacing an existing output file (a timestamped backup is m                                                                                                                        ade)",
    )

    parser.add_argument(
        "--max-rule-bytes",
        type=int,
        default=1024 * 1024,
        help="Maximum bytes accepted for one multiline rule before treating it a                                                                                                                        s malformed",
    )

    parser.add_argument(
        "--max-rule-lines",
        type=int,
        default=256,
        help="Maximum lines accepted for one multiline rule before treating it a                                                                                                                        s malformed",
    )

    parser.add_argument(
        "--progress-every",
        type=int,
        default=10000,
        help="Print a progress message after this many rules (0 disables interva                                                                                                                        l messages)",
    )

    return parser


def load_classifications(path: Optional[Path]) -> Dict[str, int]:
    """Read Suricata 'config classification' entries into {classtype: priority}.                                                                                                                        """

    classifications: Dict[str, int] = {}

    if path is None:
        return classifications

    if not path.is_file():
        raise FileNotFoundError(
            f"Classification file not found: {path}"
        )

    pattern = re.compile(
        r"^\s*config\s+classification\s*:\s*([^,]+),\s*([^,]+),\s*(\d+)\s*$",
        re.IGNORECASE,
    )

    with path.open("r", encoding="utf-8", errors="replace") as handle:

        for line in handle:

            stripped = line.split("#", 1)[0].strip()

            if not stripped:
                continue

            match = pattern.match(stripped)

            if match:
                name = match.group(1).strip().lower()
                priority = int(match.group(3))
                classifications[name] = priority

    return classifications


# ---------------------------------------------------------------------------
# Efficient rule reader
# ---------------------------------------------------------------------------

def iter_rule_blocks(
    path: Path,
    max_rule_bytes: int = 1024 * 1024,
    max_rule_lines: int = 256,
) -> Iterator[Tuple[int, str, Optional[Tuple[int, int]]]]:
    """
    Yield (starting_line, raw_rule, (opening_paren, closing_paren)).

    Rule text is scanned incrementally: only newly read characters are
    examined. This avoids repeatedly scanning a growing multiline rule,
    which caused the previous implementation to become very slow on large
    feeds or malformed rules.

    If a new rule header appears before the current rule closes, or a rule
    exceeds the safety limits, the incomplete rule is yielded with bounds=None.
    """

    raw_parts = None
    raw_length = 0
    start_line = None

    in_quote = False
    escaped = False
    depth = 0
    open_index = None

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
        newline=""
    ) as handle:

        for line_number, line in enumerate(handle, 1):

            is_header = bool(header_re.match(line))

            # A new rule header means the previous block never closed.
            if raw_parts is not None and is_header:

                yield start_line, "".join(raw_parts), None

                raw_parts = None
                raw_length = 0
                start_line = None

                in_quote = False
                escaped = False
                depth = 0
                open_index = None

            # Ignore lines which are not part of a rule.
            if raw_parts is None:

                if not is_header:
                    continue

                raw_parts = []
                start_line = line_number

                in_quote = False
                escaped = False
                depth = 0
                open_index = None

            base_offset = raw_length

            raw_parts.append(line)
            raw_length += len(line)

            bounds = None

            # Process this line only; do not rescan previously read text.
            for position, char in enumerate(line):

                absolute_position = base_offset + position

                if in_quote:

                    if escaped:
                        escaped = False
                        continue

                    if char == "\\":
                        escaped = True
                        continue

                    if char == '"':
                        in_quote = False

                    continue

                if char == '"':
                    in_quote = True

                elif char == "(":

                    if open_index is None:
                        open_index = absolute_position

                    depth += 1

                elif char == ")" and open_index is not None:

                    depth -= 1

                    if depth == 0:
                        bounds = (
                            open_index,
                            absolute_position
                        )
                        break

            if bounds is not None:

                yield start_line, "".join(raw_parts), bounds

                raw_parts = None
                raw_length = 0
                start_line = None

                in_quote = False
                escaped = False
                depth = 0
                open_index = None

                continue

            # Do not let a broken rule consume the rest of a feed.
            if (
                raw_length > max_rule_bytes
                or len(raw_parts) > max_rule_lines
            ):

                yield start_line, "".join(raw_parts), None

                raw_parts = None
                raw_length = 0
                start_line = None

                in_quote = False
                escaped = False
                depth = 0
                open_index = None

    if raw_parts is not None:
        yield start_line, "".join(raw_parts), None


# ---------------------------------------------------------------------------
# Rule option parsing
# ---------------------------------------------------------------------------

def mask_quoted_strings(text: str) -> str:
    """Replace quoted-string characters with spaces, preserving positions."""

    result = list(text)

    in_quote = False
    escaped = False

    for index, char in enumerate(text):

        if in_quote:

            if char not in "\r\n":
                result[index] = " "

            if escaped:
                escaped = False
                continue

            if char == "\\":
                escaped = True
                continue

            if char == '"':
                in_quote = False

        elif char == '"':
            result[index] = " "
            in_quote = True

    return "".join(result)


def get_rule_priority(
    options: str,
    classifications: Dict[str, int]
) -> Optional[int]:
    """Return explicit priority, or the priority associated with classtype."""

    explicit = PRIORITY_RE.search(options)

    if explicit:
        return int(explicit.group(1))

    classtype = CLASSTYPE_RE.search(options)

    if classtype:
        return classifications.get(
            classtype.group(1).lower()
        )

    return None


def identify_protocols(
    header_protocol: str,
    masked_options: str
) -> Set[str]:
    """Identify protocol hints from the rule header and app-layer keywords."""

    header_protocol = header_protocol.lower()

    detected: Set[str] = {header_protocol}

    app_layer = APP_LAYER_RE.search(masked_options)

    if app_layer:
        detected.add(app_layer.group(1).lower())

    for protocol, pattern in APP_KEYWORD_PATTERNS.items():

        if pattern.search(masked_options):
            detected.add(protocol)

    # Older HTTP rule keywords (pre sticky-buffer syntax).
    legacy_pattern = (
        r"\b(?:"
        + "|".join(
            re.escape(keyword)
            for keyword in HTTP_LEGACY_KEYWORDS
        )
        + r")\b"
    )

    if re.search(
        legacy_pattern,
        masked_options,
        re.IGNORECASE
    ):
        detected.add("http")

    # Older TLS/SSL keywords are also used in feeds.
    if re.search(
        r"\b(?:ssl_version|ssl_state|ssl_cert_subject|ssl_issuer|"
        r"ssl_serial|ssl_fingerprint|ssl_notbefore|ssl_notafter|ssl_sni)\b",
        masked_options,
        re.IGNORECASE,
    ):
        detected.add("tls")

    return detected


def convert_alert_to_drop(raw_rule: str) -> str:
    """Change only the leading alert action to drop, preserving the rule text.""                                                                                                                        "

    return re.sub(
        r"^(\s*)alert(?=\s+)",
        r"\1drop",
        raw_rule,
        count=1,
        flags=re.IGNORECASE,
    )


# ---------------------------------------------------------------------------
# Main scan and output
# ---------------------------------------------------------------------------

def make_backup(output_path: Path) -> Path:

    timestamp = dt.datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )

    backup_path = output_path.with_name(
        f"{output_path.name}.{timestamp}.bak"
    )

    shutil.copy2(output_path, backup_path)

    return backup_path


def main() -> int:

    parser = build_argument_parser()
    args = parser.parse_args()

    rules_root = args.rules_dir.expanduser().resolve()

    if not rules_root.is_dir():
        parser.error(
            f"Rules directory does not exist or is not a directory: {rules_root}                                                                                                                        "
        )

    if args.max_rule_bytes < 1 or args.max_rule_lines < 1:
        parser.error(
            "--max-rule-bytes and --max-rule-lines must be greater than zero"
        )

    if args.progress_every < 0:
        parser.error(
            "--progress-every cannot be negative"
        )

    classification_path = (
        args.classification.expanduser().resolve()
        if args.classification is not None
        else None
    )

    classifications = load_classifications(
        classification_path
    )

    output_path = (
        args.output_file.expanduser().resolve()
        if args.output_file is not None
        else (rules_root.parent / "filtered.rules").resolve()
    )

    if args.apply and output_path.exists() and not args.force:

        parser.error(
            f"Output already exists: {output_path}\n"
            "Use --force to replace it (a timestamped backup will be created)."
        )

    rule_files = sorted(
        path for path in rules_root.rglob("*.rules")
        if path.is_file() and path.resolve() != output_path
    )

    if not rule_files:

        print(
            f"No .rules files found under: {rules_root}",
            file=sys.stderr
        )

        return 1

    protocols_filter = args.protocol
    priorities_filter = args.priorities

    print(f"Source rules directory : {rules_root}")
    print(f"Rule files found       : {len(rule_files)}")
    print(f"Classification entries: {len(classifications)}")

    print(
        "Priority filter        : "
        + (
            ", ".join(
                str(x)
                for x in sorted(priorities_filter)
            )
            if priorities_filter
            else "all"
        )
    )

    print(
        "Protocol filter        : "
        + (
            ", ".join(sorted(protocols_filter))
            if protocols_filter
            else "all"
        )
    )

    print(f"Output file            : {output_path}")

    print(
        f"Mode                   : "
        f"{'WRITE' if args.apply else 'DRY RUN (no file written)'}"
    )

    print()

    counts = Counter()
    protocol_counts = Counter()
    action_counts = Counter()

    selected_count = 0
    converted_count = 0

    temp_path = None
    output_handle = None

    try:

        if args.apply:

            output_path.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            fd, temp_name = tempfile.mkstemp(
                prefix=f".{output_path.name}.",
                suffix=".tmp",
                dir=str(output_path.parent),
                text=True,
            )

            temp_path = Path(temp_name)

            output_handle = os.fdopen(
                fd,
                "w",
                encoding="utf-8",
                newline=""
            )

        for file_number, path in enumerate(rule_files, 1):

            file_start_rules = counts["rules"]
            file_start_selected = selected_count

            print(
                f"[{file_number}/{len(rule_files)}] Scanning: "
                f"{path.relative_to(rules_root)}",
                flush=True,
            )

            for line_number, raw_rule, bounds in iter_rule_blocks(
                path,
                max_rule_bytes=args.max_rule_bytes,
                max_rule_lines=args.max_rule_lines,
            ):

                counts["rules"] += 1

                if (
                    args.progress_every
                    and counts["rules"] % args.progress_every == 0
                ):

                    print(
                        f"  Processed {counts['rules']:,} rules; "
                        f"selected {selected_count:,}...",
                        flush=True,
                    )

                if bounds is None:
                    counts["malformed"] += 1
                    continue

                header_match = header_re.match(raw_rule)

                if not header_match:
                    counts["invalid_header"] += 1
                    continue

                action = header_match.group(1).lower()
                header_protocol = header_match.group(2).lower()

                open_index, close_index = bounds

                options = raw_rule[
                    open_index + 1:close_index
                ]

                masked_options = mask_quoted_strings(
                    options
                )

                priority = get_rule_priority(
                    masked_options,
                    classifications
                )

                if priority is None:
                    counts["unclassified"] += 1
                else:
                    counts[f"priority_{priority}"] += 1

                detected_protocols = identify_protocols(
                    header_protocol,
                    masked_options,
                )

                for detected in detected_protocols:
                    protocol_counts[detected] += 1

                # Apply priority filter.
                if priorities_filter is not None:

                    if (
                        priority is None
                        or priority not in priorities_filter
                    ):

                        counts["priority_filtered"] += 1
                        continue

                # Apply protocol filter.
                if protocols_filter is not None:

                    if (
                        "all" not in protocols_filter
                        and not (
                            detected_protocols & protocols_filter
                        )
                    ):

                        counts["protocol_filtered"] += 1
                        continue

                selected_count += 1

                action_counts[action] += 1

                if action == "alert":

                    output_rule = convert_alert_to_drop(
                        raw_rule
                    )

                    converted_count += 1

                else:
                    output_rule = raw_rule

                if output_handle is not None:

                    output_handle.write(output_rule)

                    if not output_rule.endswith(("\n", "\r")):
                        output_handle.write("\n")

            print(
                f"  Completed: "
                f"{counts['rules'] - file_start_rules:,} rules; "
                f"{selected_count - file_start_selected:,} selected",
                flush=True,
            )

        # Finish writing the temporary output file.
        if output_handle is not None:

            output_handle.flush()

            os.fsync(
                output_handle.fileno()
            )

            output_handle.close()
            output_handle = None

            # mkstemp() creates files with mode 0600 by default.
            # Suricata may run as an unprivileged user inside the container,
            # so make the completed ruleset readable before publishing it.
            os.chmod(
                temp_path,
                0o644
            )

            backup_path = None

            if output_path.exists():

                # This is only possible with --force (checked above).
                backup_path = make_backup(
                    output_path
                )

            os.replace(
                temp_path,
                output_path
            )

            temp_path = None

            if backup_path:
                print(
                    f"\nPrevious output backed up to: {backup_path}"
                )

    except Exception:

        if output_handle is not None:
            output_handle.close()
            output_handle = None

        if temp_path is not None:

            try:
                temp_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass

        raise

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    print(
        "\n================ RULE FILTER SUMMARY ================"
    )

    print(
        f"Rule files scanned       : {len(rule_files):,}"
    )

    print(
        f"Rule blocks processed    : {counts['rules']:,}"
    )

    print(
        f"Malformed/incomplete     : {counts['malformed']:,}"
    )

    print(
        f"Invalid headers          : {counts['invalid_header']:,}"
    )

    print(
        f"Rules without priority   : {counts['unclassified']:,}"
    )

    print(
        f"Filtered by priority     : {counts['priority_filtered']:,}"
    )

    print(
        f"Filtered by protocol     : {counts['protocol_filtered']:,}"
    )

    print(
        f"Selected rules           : {selected_count:,}"
    )

    print(
        f"Alert rules converted    : {converted_count:,}"
    )

    if action_counts:

        print("\nSelected rule actions:")

        for action, count in sorted(action_counts.items()):

            print(
                f"  {action:<12} {count:,}"
            )

    if protocol_counts:

        print(
            "\nDetected protocol occurrences "
            "(rules may count under multiple protocols):"
        )

        for protocol, count in sorted(protocol_counts.items()):

            print(
                f"  {protocol:<12} {count:,}"
            )

    if args.apply:

        print(
            f"\nFiltered rules written to: {output_path}"
        )

    else:

        print(
            "\nDry run only: no output file was written. "
            "Add --apply to write the rules."
        )

    print(
        "====================================================="
    )

    print(
        "Reminder: validate the generated rules with Suricata -T before reloadin                                                                                                                        g."
    )

    return 0


if __name__ == "__main__":

    try:

        raise SystemExit(
            main()
        )

    except KeyboardInterrupt:

        print(
            "\nInterrupted by user.",
            file=sys.stderr
        )

        raise SystemExit(130)

    except (OSError, UnicodeError) as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr
        )

        raise SystemExit(1)
