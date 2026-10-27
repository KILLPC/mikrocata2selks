#!/usr/bin/env python3

import argparse
import re
import shutil
from datetime import datetime
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Convert Suricata alert rules with priority 1 or 2 to drop."
)
parser.add_argument(
    "--rules-dir",
    default="rules-data/rules",
    help="Directory containing the active Suricata rules",
)
parser.add_argument(
    "--classification",
    default="suricata-config/classification.config",
    help="Suricata classification.config file",
)
parser.add_argument(
    "--apply",
    action="store_true",
    help="Apply changes; without this flag, only preview",
)
args = parser.parse_args()

rules_root = Path(args.rules_dir).resolve()
classification_file = Path(args.classification).resolve()

if not rules_root.is_dir():
    raise SystemExit(f"Rules directory not found: {rules_root}")

if not classification_file.is_file():
    raise SystemExit(
        f"Classification file not found: {classification_file}\n"
        "Pass its actual path with --classification."
    )

# Map classtype names to their numeric priorities.
class_priorities = {}

for line in classification_file.read_text(errors="replace").splitlines():
    line = line.strip()

    if not line or line.startswith("#"):
        continue

    match = re.match(r"^config\s+classification:\s*(.*)$", line)
    if not match:
        continue

    parts = [part.strip() for part in match.group(1).split(",")]

    if len(parts) >= 3 and parts[-1].isdigit():
        class_priorities[parts[0].lower()] = int(parts[-1])

# Rule options.
priority_re = re.compile(r"\bpriority\s*:\s*(\d+)\s*;")
classtype_re = re.compile(r"\bclasstype\s*:\s*([\w-]+)\s*;")
sid_re = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
msg_re = re.compile(r'\bmsg\s*:\s*"((?:\\.|[^"])*)"')

candidates = []

for path in sorted(rules_root.rglob("*.rules")):
    lines = path.read_text(errors="replace").splitlines(keepends=True)

    for line_number, line in enumerate(lines, 1):
        # Only convert rules whose action is currently alert.
        action_match = re.match(r"^(\s*)alert\s+", line)

        if not action_match:
            continue

        # Ignore comments and incomplete/non-rule lines.
        if line.lstrip().startswith("#") or "(" not in line:
            continue

        # An explicit priority takes precedence over classtype.
        priority_match = priority_re.search(line)
        class_match = classtype_re.search(line)

        if priority_match:
            priority = int(priority_match.group(1))
            priority_source = "explicit priority"
        elif class_match:
            classtype = class_match.group(1).lower()
            priority = class_priorities.get(classtype)
            priority_source = f"classtype:{classtype}"
        else:
            continue

        if priority not in (1, 2):
            continue

        sid_match = sid_re.search(line)
        msg_match = msg_re.search(line)

        candidates.append({
            "path": path,
            "line_number": line_number,
            "line": line,
            "priority": priority,
            "source": priority_source,
            "sid": sid_match.group(1) if sid_match else "?",
            "msg": msg_match.group(1) if msg_match else "(no msg)",
        })

print(f"Rules directory: {rules_root}")
print(f"Classification file: {classification_file}")
print(f"Matching alert rules found: {len(candidates)}")
print()

for item in candidates:
    relative = item["path"].relative_to(rules_root)
    print(
        f"Priority {item['priority']} | SID {item['sid']} | "
        f"{relative}:{item['line_number']} | {item['msg']}"
    )

if not args.apply:
    print("\nPREVIEW ONLY — no rules were modified.")
    print("Review the candidates before running with --apply.")
    raise SystemExit(0)

if not candidates:
    print("\nNothing to change.")
    raise SystemExit(0)

# Backups are kept outside the live rules directory.
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup_root = rules_root.parent / f"{rules_root.name}-backup-{timestamp}"

by_file = {}

for item in candidates:
    by_file.setdefault(item["path"], {})[item["line_number"]] = item

for path, changes in by_file.items():
    relative = path.relative_to(rules_root)
    backup_path = backup_root / relative
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, backup_path)

    lines = path.read_text(errors="replace").splitlines(keepends=True)

    for line_number in changes:
        lines[line_number - 1] = re.sub(
            r"^(\s*)alert(\s+)",
            r"\1drop\2",
            lines[line_number - 1],
            count=1,
        )

    path.write_text("".join(lines))

print(f"\nChanged {len(candidates)} rules in {len(by_file)} files.")
print(f"Backups saved to: {backup_root}")
