#!/usr/bin/env python3
"""Build per-source Suricata and ICAPSuricata rule files from shared feeds.

The original provider files in suricata/rules-data/rules are inputs only and
are never modified. Suricata outputs are <source>.suricata.rules; ICAP outputs
are <source>.icapsuricata.rules. The one Suricata exclusions.txt is applied to
both outputs. ICAP DROP conversion covers rules from all protocols and reads its
severity selection from a marker comment in the ICAP suricata.yaml.

CLI:
    applyruleset.sh          # use ICAP YAML marker (default 1)
    applyruleset.sh 1        # set marker to 1, then apply
    applyruleset.sh 1,2      # set marker to 1,2, then apply

The marker also accepts 1,2,3 for forward compatibility when edited directly
in YAML.  This CLI intentionally accepts only 1 or 1,2 at present.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Optional


SCRIPT_PATH = Path(__file__).resolve()
SURICATA_RULES_DATA = SCRIPT_PATH.parent
REPO_ROOT = SURICATA_RULES_DATA.parents[1]
SURICATA_RULES_DIR = SURICATA_RULES_DATA / "rules"
ICAP_RULES_DATA = REPO_ROOT / "icapsuricata" / "rules-data"
ICAP_RULES_DIR = ICAP_RULES_DATA / "rules"
SURICATA_YAML = REPO_ROOT / "suricata" / "suricata-config" / "suricata.yaml"
ICAP_YAML = REPO_ROOT / "icapsuricata" / "suricata-config" / "suricata.yaml"
EXCLUSIONS_FILE = SURICATA_RULES_DATA / "exclusions.txt"
ICAP_CONVERTER = ICAP_RULES_DATA / "convert_severity_to_drop.py"
CLASSIFICATION_FILE = REPO_ROOT / "icapsuricata" / "suricata-config" / "classification.config"
BACKUP_ROOT = Path("/var/backups/mikrocata2selks/per-source-ruleset")

RULE_HEADER_RE = re.compile(
    r"^\s*(?:alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+\S+\s+",
    re.IGNORECASE,
)
SID_RE = re.compile(r"(?:^|;)\s*sid\s*:\s*(\d+)\s*(?:;|$)", re.IGNORECASE)

# Exact list-item parser, including commented items such as '#- emerging-dns.rules'.
YAML_LIST_ITEM_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<comment>#\s*)?(?P<dash>-\s*)"
    r"(?:(?P<double>\"[^\"]+\")|(?P<single>'[^']+')|(?P<plain>[^#\s]+))"
    r"(?P<tail>[ \t]*(?:#.*)?)?(?P<newline>\r?\n)?$"
)
RULE_FILES_KEY_RE = re.compile(r"^(?P<indent>[ \t]*)rule-files\s*:\s*(?:#.*)?(?:\r?\n)?$")
TOP_LEVEL_KEY_RE = re.compile(r"^[ \t]*[A-Za-z0-9_.-]+\s*:")
SEVERITY_MARKER_RE = re.compile(
    r"^[ \t]*#\s*(?:MIKRO-)?NGFW\s+Severity\s+drop\s*:\s*([0-9]+(?:,[0-9]+)*)\s*$",
    re.IGNORECASE,
)
SEVERITY_MARKER_PREFIX_RE = re.compile(
    r"^[ \t]*#\s*(?:MIKRO-)?NGFW\s+Severity\s+drop\s*:",
    re.IGNORECASE,
)
SUPPORTED_MARKER_VALUES = {"1", "1,2", "1,2,3"}
SUPPORTED_CLI_VALUES = {"1", "1,2"}


def fail(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_converter(path: Path):
    """Load the existing ICAP converter without changing or copying it."""
    if not path.is_file():
        fail(f"ICAP severity converter not found: {path}")
    spec = importlib.util.spec_from_file_location("daminet_icap_converter", path)
    if spec is None or spec.loader is None:
        fail(f"Unable to load ICAP severity converter: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    required = (
        "iter_rule_blocks", "header_re", "mask_quoted_strings", "get_rule_priority",
        "convert_alert_to_drop", "replace_rule_action",
        "NOALERT_RE", "BLOCKING_ACTIONS", "load_classifications",
    )
    missing = [name for name in required if not hasattr(module, name)]
    if missing:
        fail(
            "The installed ICAP converter does not expose the expected current "
            f"conversion helpers ({', '.join(missing)}). Refusing to guess its semantics."
        )
    return module


def read_exclusions(path: Path) -> set[int]:
    """Read positive numeric SIDs; blank lines and full-line comments are ignored."""
    if not path.is_file():
        raise FileNotFoundError(
            f"Shared SID exclusions file is missing or not a regular file: {path}. "
            "Refusing to apply rules without the configured exclusions."
        )
    sids: set[int] = set()
    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line_number, raw in enumerate(handle, 1):
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            # Allow a trailing comment while keeping the active SID token strict.
            token = value.split(None, 1)[0]
            if not re.fullmatch(r"[1-9][0-9]{0,9}", token):
                raise ValueError(
                    f"Invalid active exclusions entry at {path}:{line_number}: {value!r}"
                )
            sid = int(token)
            if sid > 4_294_967_295:
                raise ValueError(f"SID outside valid range at {path}:{line_number}: {sid}")
            sids.add(sid)
    return sids


def source_rule_files(source_dir: Path) -> list[Path]:
    """Return direct source .rules files, excluding previous generated outputs."""
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Shared source rules directory not found: {source_dir}")
    excluded_names = {"filtered.rules", "ruleset-manager-candidate.rules"}
    result = []
    for path in sorted(source_dir.iterdir(), key=lambda p: p.name.lower()):
        if not path.is_file() or path.suffix != ".rules":
            continue
        if path.name in excluded_names:
            continue
        if path.name.endswith((".suricata.rules", ".icapsuricata.rules")):
            continue
        result.append(path)
    if not result:
        raise RuntimeError(f"No source .rules files found in {source_dir}")
    return result


def mask_quoted_strings(text: str) -> str:
    """Mask quoted string characters so a string containing 'sid:' is not matched."""
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


def _rule_balance(line: str, depth: int, in_quote: bool, escaped: bool, seen_open: bool):
    for char in line:
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
            depth += 1
            seen_open = True
        elif char == ")" and seen_open:
            depth -= 1
    return depth, in_quote, escaped, seen_open


def write_commented_rule(handle, raw: str, sid: str) -> None:
    """Write a complete rule block as inert, auditable comment lines."""
    newline = "\r\n" if "\r\n" in raw else "\n"
    handle.write(f"# MIKRO-NGFW excluded SID: {sid}{newline}")
    for raw_line in raw.splitlines(keepends=True):
        if raw_line.endswith("\r\n"):
            handle.write("# " + raw_line[:-2] + "\r\n")
        elif raw_line.endswith(("\n", "\r")):
            handle.write("# " + raw_line[:-1] + raw_line[-1:])
        else:
            handle.write("# " + raw_line + newline)


def filter_excluded_sids(source: Path, destination: Path, excluded_sids: set[int]) -> int:
    """Copy rules while commenting out complete rule blocks with excluded SIDs.

    Non-rule lines are preserved verbatim. Multiline rules and quoted
    parentheses are supported. Incomplete/malformed blocks are preserved and
    reported rather than silently discarded.
    """
    excluded_count = 0
    malformed_count = 0
    current: list[str] = []
    depth = 0
    in_quote = False
    escaped = False
    seen_open = False

    def write_block(handle, block: list[str], complete: bool) -> None:
        nonlocal excluded_count, malformed_count
        raw = "".join(block)
        if not complete:
            malformed_count += 1
            handle.write(raw)
            return
        sid_match = SID_RE.search(mask_quoted_strings(raw))
        if sid_match and int(sid_match.group(1)) in excluded_sids:
            excluded_count += 1
            # Keep the excluded signature visible for auditing/check_exclusions,
            # but comment every physical line so multiline rules cannot leak
            # active continuation text into Suricata's parser.
            write_commented_rule(handle, raw, sid_match.group(1))
            return
        handle.write(raw)

    with source.open("r", encoding="utf-8", errors="surrogateescape", newline="") as input_handle, \
         destination.open("w", encoding="utf-8", errors="surrogateescape", newline="") as output_handle:
        for line in input_handle:
            is_new_header = bool(RULE_HEADER_RE.match(line))
            if current and is_new_header:
                # Previous block never closed: preserve it verbatim and fail-safe.
                write_block(output_handle, current, False)
                current = []
                depth = 0
                in_quote = False
                escaped = False
                seen_open = False

            if not current:
                if not is_new_header:
                    output_handle.write(line)
                    continue
                current = [line]
            else:
                current.append(line)

            depth, in_quote, escaped, seen_open = _rule_balance(
                line, depth, in_quote, escaped, seen_open
            )
            if seen_open and depth == 0 and not in_quote:
                write_block(output_handle, current, True)
                current = []
                depth = 0
                in_quote = False
                escaped = False
                seen_open = False
        if current:
            write_block(output_handle, current, False)
        output_handle.flush()
        os.fsync(output_handle.fileno())

    if malformed_count:
        print(
            f"WARNING: preserved {malformed_count} incomplete/malformed rule block(s) "
            f"from {source.name}; they were not SID-filtered."
        )
    return excluded_count


def build_icap_file(
    source: Path,
    destination: Path,
    converter,
    classifications: dict[str, int],
    severities: set[int],
    excluded_sids: set[int],
) -> tuple[int, int, int]:
    """Build one ICAP source output and apply severity conversion to all protocols.

    Excluded rule blocks are retained as comments and never converted to DROP.
    All other valid rules remain in the output. Selected-priority ALERT rules
    are converted to DROP regardless of protocol; noalert helpers are preserved.
    """
    counts = {"processed": 0, "converted": 0, "excluded": 0}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", errors="replace", newline="") as out:
        for _line_number, raw_rule, bounds in converter.iter_rule_blocks(source):
            if bounds is None:
                # Match the converter's existing behavior: malformed blocks are skipped.
                continue
            header_match = converter.header_re.match(raw_rule)
            if not header_match:
                continue
            counts["processed"] += 1
            action = header_match.group(1).lower()
            open_index, close_index = bounds
            options = raw_rule[open_index + 1:close_index]
            masked_options = converter.mask_quoted_strings(options)
            sid_match = SID_RE.search(masked_options)
            if sid_match and int(sid_match.group(1)) in excluded_sids:
                sid = sid_match.group(1)
                counts["excluded"] += 1
                write_commented_rule(out, raw_rule, sid)
                continue

            priority = converter.get_rule_priority(masked_options, classifications)
            selected_priority = priority is not None and priority in severities
            noalert = bool(converter.NOALERT_RE.search(masked_options))
            if action == "alert":
                if selected_priority and not noalert:
                    output_rule = converter.convert_alert_to_drop(raw_rule)
                    counts["converted"] += 1
                else:
                    output_rule = raw_rule
            elif action in converter.BLOCKING_ACTIONS and not selected_priority:
                # Same default as the existing converter: only selected
                # priorities remain blocking; non-selected authored blocks
                # are downgraded to ALERT unless explicitly opted out.
                output_rule = converter.replace_rule_action(raw_rule, "alert")
            else:
                output_rule = raw_rule

            out.write(output_rule)
            if not output_rule.endswith(("\n", "\r")):
                out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.chmod(destination, 0o644)
    return counts["processed"], counts["converted"], counts["excluded"]


def _yaml_entry(line: str):
    match = YAML_LIST_ITEM_RE.match(line)
    if not match:
        return None
    if match.group("double"):
        name = match.group("double")[1:-1]
        token = match.group("double")
    elif match.group("single"):
        name = match.group("single")[1:-1]
        token = match.group("single")
    else:
        name = match.group("plain")
        token = match.group("plain")
    return match, name, token


def update_yaml_rule_files(text: str, source_names: Iterable[str], engine_suffix: str) -> tuple[str, dict[str, int]]:
    """Switch active raw source refs to engine outputs and append missing feeds.

    Commented-out refs count as intentional disables and are never enabled.
    Entries for absent sources and the other engine's suffix are left alone.
    """
    lines = text.splitlines(keepends=True)
    keys = [i for i, line in enumerate(lines) if RULE_FILES_KEY_RE.match(line)]
    if len(keys) != 1:
        raise RuntimeError(
            f"Expected exactly one active top-level rule-files: section; found {len(keys)}"
        )
    start = keys[0]
    key_match = RULE_FILES_KEY_RE.match(lines[start])
    assert key_match is not None
    key_indent = len(key_match.group("indent").expandtabs(8))
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if indent <= key_indent and TOP_LEVEL_KEY_RE.match(line):
            end = i
            break

    source_list = sorted(set(source_names), key=str.lower)
    source_set = set(source_list)
    target_by_source = {
        name: name[:-6] + engine_suffix + ".rules"
        for name in source_list
        if name.endswith(".rules")
    }
    seen_active: set[str] = set()
    seen_commented: set[str] = set()
    item_indents: list[str] = []
    updated = list(lines)

    # First pass collects intentionally commented source/output names.
    parsed_entries: dict[int, tuple[re.Match, str, str]] = {}
    for i in range(start + 1, end):
        parsed = _yaml_entry(lines[i])
        if not parsed:
            continue
        match, name, token = parsed
        parsed_entries[i] = parsed
        item_indents.append(match.group("indent"))
        if match.group("comment"):
            if name in source_set or name in target_by_source.values():
                seen_commented.add(name)

    # Second pass updates only active raw source entries.
    for i, (match, name, token) in parsed_entries.items():
        if match.group("comment"):
            continue
        if name in target_by_source.values():
            seen_active.add(name)
            continue
        if name not in target_by_source:
            continue
        target = target_by_source[name]
        seen_active.add(target)
        quote = '"' if match.group("double") else ("'" if match.group("single") else "")
        token_new = f"{quote}{target}{quote}"
        updated[i] = (
            match.group("indent") + (match.group("comment") or "") +
            match.group("dash") + token_new + (match.group("tail") or "") +
            (match.group("newline") or "")
        )

    append: list[str] = []
    newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
    if item_indents:
        list_indent = item_indents[0]
    else:
        list_indent = key_match.group("indent") + "  "

    for source_name, target_name in target_by_source.items():
        # Correct-engine active entries are already enabled. The opposite
        # engine suffix is never counted as a match.
        if target_name in seen_active:
            continue
        if source_name in seen_commented or target_name in seen_commented:
            continue
        append.append(f"{list_indent}- {target_name}{newline}")

    if append and end > start and not updated[end - 1].endswith(("\n", "\r")):
        updated[end - 1] += newline
    updated[end:end] = append
    stats = {
        "updated_active_refs": sum(
            1 for i, (match, name, _token) in parsed_entries.items()
            if not match.group("comment") and name in target_by_source
        ),
        "kept_commented_refs": len(seen_commented),
        "appended_refs": len(append),
    }
    return "".join(updated), stats


def update_severity_marker(text: str, cli_value: Optional[str]) -> tuple[str, str]:
    """Read or persist '#MIKRO-NGFW Severity drop:<value>' in ICAP YAML."""
    lines = text.splitlines(keepends=True)
    marker_lines: list[int] = []
    marker_values: list[str] = []
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        if SEVERITY_MARKER_PREFIX_RE.match(body):
            match = SEVERITY_MARKER_RE.match(body)
            if not match:
                raise RuntimeError(f"Malformed NGFW severity marker in ICAP YAML: {body!r}")
            marker_lines.append(index)
            marker_values.append(match.group(1))
    if len(marker_lines) > 1:
        raise RuntimeError("More than one NGFW Severity drop marker exists in ICAP suricata.yaml")

    if cli_value is not None:
        if cli_value not in SUPPORTED_CLI_VALUES:
            raise RuntimeError("applyruleset.sh accepts only '1' or '1,2' as an argument")
        severity = cli_value
    elif marker_values:
        severity = marker_values[0]
    else:
        severity = "1"

    if severity not in SUPPORTED_MARKER_VALUES:
        raise RuntimeError(
            f"Unsupported ICAP YAML severity marker {severity!r}; expected 1, 1,2, or 1,2,3"
        )

    marker_text = f"#MIKRO-NGFW Severity drop:{severity}"
    if marker_lines:
        index = marker_lines[0]
        old = lines[index]
        newline = "\r\n" if old.endswith("\r\n") else ("\n" if old.endswith("\n") else "")
        indent = old[:len(old) - len(old.lstrip(" \t"))]
        replacement = indent + marker_text + newline
        if replacement != old:
            lines[index] = replacement
    else:
        rule_key_index = next((i for i, line in enumerate(lines) if RULE_FILES_KEY_RE.match(line)), None)
        if rule_key_index is None:
            raise RuntimeError("Cannot insert severity marker: ICAP YAML has no rule-files: section")
        newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
        lines.insert(rule_key_index, marker_text + newline)
    return "".join(lines), severity


def atomic_write_text(path: Path, content: str) -> None:
    original = path.stat()
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(original.st_mode))
        try:
            os.chown(temporary, original.st_uid, original.st_gid)
        except PermissionError:
            pass
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def backup_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)
        info = source.stat()
        try:
            os.chown(destination, info.st_uid, info.st_gid)
        except PermissionError:
            pass


def restore_file(backup: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.restore.", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        shutil.copy2(backup, temporary)
        info = backup.stat()
        try:
            os.chown(temporary, info.st_uid, info.st_gid)
        except PermissionError:
            pass
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_reload(container: str) -> None:
    command = ["docker", "exec", container, "suricatasc", "-c", "ruleset-reload-nonblocking"]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no output").strip()
        raise RuntimeError(f"{container} rule reload failed (exit {result.returncode}): {detail[-1500:]}")
    output = (result.stdout or result.stderr or "").strip()
    print(f"Reload requested: {container}" + (f" — {output[-300:]}" if output else ""))


def validate_environment() -> object:
    required = (
        SURICATA_RULES_DIR, ICAP_RULES_DIR, SURICATA_YAML, ICAP_YAML,
        ICAP_CONVERTER, CLASSIFICATION_FILE,
    )
    for path in required:
        if not path.exists():
            raise FileNotFoundError(f"Required path not found: {path}")
    if not SURICATA_YAML.is_file() or not ICAP_YAML.is_file():
        raise RuntimeError("Both engine suricata.yaml paths must be regular files")
    if not shutil.which("docker"):
        raise RuntimeError("docker executable not found; cannot preserve the existing reload behavior")
    converter = load_converter(ICAP_CONVERTER)
    return converter


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="applyruleset.sh",
        description="Generate per-source Suricata and ICAPSuricata rules, apply shared SID exclusions, and reload both engines.",
    )
    parser.add_argument(
        "severity", nargs="?", choices=sorted(SUPPORTED_CLI_VALUES),
        help="Optional ICAP DROP severity override: 1 or 1,2 (persisted in icapsuricata suricata.yaml)",
    )
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        fail("Run applyruleset.sh as root (the existing cron/portal execution is expected to be root).")

    lock_fd: Optional[int] = None
    try:
        lock_path = Path("/run/lock/mikrocata2selks-applyruleset.lock")
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock_fd)
            lock_fd = None
            fail("Another applyruleset operation is already running; refusing to overlap.")

        converter = validate_environment()
        sources = source_rule_files(SURICATA_RULES_DIR)
        source_names = [path.name for path in sources]
        excluded_sids = read_exclusions(EXCLUSIONS_FILE)

        with SURICATA_YAML.open("r", encoding="utf-8", errors="surrogateescape", newline="") as handle:
            suri_yaml_original = handle.read()
        with ICAP_YAML.open("r", encoding="utf-8", errors="surrogateescape", newline="") as handle:
            icap_yaml_original = handle.read()
        icap_yaml_with_marker, severity_text = update_severity_marker(icap_yaml_original, args.severity)
        severity_set = {int(part) for part in severity_text.split(",")}
        suri_yaml_new, suri_yaml_stats = update_yaml_rule_files(
            suri_yaml_original, source_names, ".suricata"
        )
        icap_yaml_new, icap_yaml_stats = update_yaml_rule_files(
            icap_yaml_with_marker, source_names, ".icapsuricata"
        )

        classifications = converter.load_classifications(CLASSIFICATION_FILE)
        timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup_dir = BACKUP_ROOT / timestamp
        backup_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        os.chmod(backup_dir, 0o700)

        # Staging directories live on the destination filesystems so final
        # os.replace() operations are atomic.
        with tempfile.TemporaryDirectory(prefix=".ngfw-stage-suri-", dir=SURICATA_RULES_DIR) as suri_tmp_name, \
             tempfile.TemporaryDirectory(prefix=".ngfw-stage-icap-", dir=ICAP_RULES_DIR) as icap_tmp_name:
            suri_stage = Path(suri_tmp_name)
            icap_stage = Path(icap_tmp_name)
            staged_outputs: list[tuple[Path, Path, str]] = []
            total_suri_excluded = 0
            total_icap_excluded = 0
            total_icap_converted = 0

            print(f"Shared source directory : {SURICATA_RULES_DIR}")
            print(f"Source rule files       : {len(sources)}")
            print(f"Shared SID exclusions   : {len(excluded_sids)} from {EXCLUSIONS_FILE}")
            print(f"ICAP severity DROP      : {severity_text}")
            print("ICAP protocol filter    : none (all protocols included)")

            for source in sources:
                stem = source.name[:-6]
                suri_name = f"{stem}.suricata.rules"
                icap_name = f"{stem}.icapsuricata.rules"
                suri_stage_file = suri_stage / suri_name
                icap_stage_file = icap_stage / icap_name

                excluded = filter_excluded_sids(source, suri_stage_file, excluded_sids)
                total_suri_excluded += excluded
                staged_outputs.append((suri_stage_file, SURICATA_RULES_DIR / suri_name, "suricata"))

                _processed, converted, excluded_icap = build_icap_file(
                    source, icap_stage_file, converter, classifications, severity_set, excluded_sids
                )
                total_icap_converted += converted
                total_icap_excluded += excluded_icap
                staged_outputs.append((icap_stage_file, ICAP_RULES_DIR / icap_name, "icapsuricata"))
                print(
                    f"  {source.name}: Suricata exclusions={excluded}; "
                    f"ICAP DROP conversions={converted}; all protocols; "
                    f"ICAP exclusions={excluded_icap}"
                )

            # Back up the two YAMLs and every target output before changing any
            # live file. Existing source .rules files are never backed up or edited.
            backup_file(SURICATA_YAML, backup_dir / "suricata.yaml")
            backup_file(ICAP_YAML, backup_dir / "icapsuricata-suricata.yaml")
            old_targets: set[Path] = set()
            for _stage, target, engine in staged_outputs:
                if target in old_targets:
                    raise RuntimeError(f"Duplicate generated output target: {target}")
                old_targets.add(target)
                if target.exists():
                    backup_file(target, backup_dir / "outputs" / engine / target.name)

            new_targets: list[Path] = []
            replaced_targets: list[Path] = []
            try:
                for stage, target, _engine in staged_outputs:
                    if target.exists():
                        replaced_targets.append(target)
                    else:
                        new_targets.append(target)
                    os.replace(stage, target)
                    os.chmod(target, 0o644)

                atomic_write_text(SURICATA_YAML, suri_yaml_new)
                atomic_write_text(ICAP_YAML, icap_yaml_new)

                # Keep existing beta reload semantics: reload both containers.
                run_reload("suricata")
                run_reload("icapsuricata")
            except Exception:
                print("Apply/reload failed; restoring the previous YAML and generated outputs...", file=sys.stderr)
                # Restore YAMLs unconditionally because one write may have succeeded.
                restore_file(backup_dir / "suricata.yaml", SURICATA_YAML)
                restore_file(backup_dir / "icapsuricata-suricata.yaml", ICAP_YAML)
                for target in reversed(replaced_targets):
                    backup = backup_dir / "outputs" / ("suricata" if target.parent == SURICATA_RULES_DIR else "icapsuricata") / target.name
                    if backup.exists():
                        restore_file(backup, target)
                for target in new_targets:
                    try:
                        target.unlink()
                    except FileNotFoundError:
                        pass
                # Best-effort reload of the restored configuration.
                for container in ("suricata", "icapsuricata"):
                    try:
                        run_reload(container)
                    except Exception as rollback_error:
                        print(f"WARNING: rollback reload for {container} failed: {rollback_error}", file=sys.stderr)
                raise

        print("\n================ APPLY SUMMARY ================")
        print(f"Source files processed             : {len(sources)}")
        print(f"Suricata per-source files generated: {len(sources)}")
        print(f"ICAP per-source files generated    : {len(sources)}")
        print(f"SID exclusions applied to Suricata : {total_suri_excluded}")
        print(f"SID exclusions applied to ICAP     : {total_icap_excluded}")
        print(f"ICAP ALERT -> DROP conversions     : {total_icap_converted}")
        print(f"Suricata YAML raw refs converted   : {suri_yaml_stats['updated_active_refs']}")
        print(f"Suricata YAML refs appended        : {suri_yaml_stats['appended_refs']}")
        print(f"Suricata YAML commented refs kept  : {suri_yaml_stats['kept_commented_refs']}")
        print(f"ICAP YAML raw refs converted      : {icap_yaml_stats['updated_active_refs']}")
        print(f"ICAP YAML refs appended           : {icap_yaml_stats['appended_refs']}")
        print(f"ICAP YAML commented refs kept     : {icap_yaml_stats['kept_commented_refs']}")
        print(f"Severity marker                   : #MIKRO-NGFW Severity drop:{severity_text}")
        print(f"Backup directory                  : {backup_dir}")
        print("Both engine reloads were requested successfully.")
        print("================================================")
        return 0

    except SystemExit:
        raise
    except Exception as exc:
        fail(str(exc))
    finally:
        if lock_fd is not None:
            os.close(lock_fd)


if __name__ == "__main__":
    raise SystemExit(main())
