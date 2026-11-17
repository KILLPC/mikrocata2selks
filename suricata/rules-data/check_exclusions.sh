#!/usr/bin/env bash

set -u

BASE_DIR="/opt/mikrocata2selks"

EXCLUSIONS_FILE="$BASE_DIR/suricata/rules-data/exclusions.txt"

SURICATA_RULES_DIR="$BASE_DIR/suricata/rules-data/rules"
ICAP_RULES_DIR="$BASE_DIR/icapsuricata/rules-data/rules"

if [[ ! -f "$EXCLUSIONS_FILE" ]]; then
    echo "ERROR: Shared exclusions file not found: $EXCLUSIONS_FILE"
    exit 1
fi

for dir in "$SURICATA_RULES_DIR" "$ICAP_RULES_DIR"; do
    if [[ ! -d "$dir" ]]; then
        echo "ERROR: Rules directory not found: $dir"
        exit 1
    fi
done

shopt -s nullglob

echo "=============================================================================================="
printf "%-10s | %-12s | %-38s | %s\n" "SID" "ENGINE" "FILE" "RULE MSG"
echo "=============================================================================================="

audit_engine() {
    local sid="$1"
    local engine="$2"
    local rules_dir="$3"
    local type="$4"

    local -a generated_rule_files=()
    local matches=""
    local match=""
    local filepath=""
    local filename=""
    local rule=""
    local msg=""
    local map_msg=""

    case "$type" in
        suricata)
            generated_rule_files=("$rules_dir"/*.suricata.rules)
            ;;
        icap)
            generated_rule_files=("$rules_dir"/*.icapsuricata.rules)
            ;;
    esac

    # Search generated rules for this SID.
    if (( ${#generated_rule_files[@]} )); then
        matches=$(grep -F -H -- "sid:${sid};" \
            "${generated_rule_files[@]}" 2>/dev/null || true)
    fi

    if [[ -n "$matches" ]]; then
        while IFS= read -r match; do
            filepath="${match%%:*}"
            rule="${match#*:}"
            filename=$(basename -- "$filepath")

            msg=$(printf '%s\n' "$rule" |
                sed -n 's/.*msg:"\([^"]*\)".*/\1/p')

            [[ -z "$msg" ]] && msg="-"

            printf "%-10s | %-12s | %-38s | %s\n" \
                "$sid" "$engine" "$filename" "$msg"
        done <<< "$matches"
    else
        # Fallback to the engine's sid-msg.map.
        if [[ -f "$rules_dir/sid-msg.map" ]]; then
            map_msg=$(awk -v sid="$sid" \
                '$1 == sid && $2 == "||" {
                    $1 = ""
                    $2 = ""
                    sub(/^[[:space:]]+/, "")
                    print
                    exit
                }' "$rules_dir/sid-msg.map")
        fi

        if [[ -n "$map_msg" ]]; then
            printf "%-10s | %-12s | %-38s | %s\n" \
                "$sid" "$engine" "sid-msg.map" "$map_msg"
        else
            printf "%-10s | %-12s | %-38s | %s\n" \
                "$sid" "$engine" "NOT FOUND" "-"
        fi
    fi
}

while IFS= read -r sid || [[ -n "$sid" ]]; do
    sid="${sid//$'\r'/}"

    # Ignore blank lines and comments.
    [[ -z "$sid" || "$sid" =~ ^[[:space:]]*# ]] && continue

    # Only numeric SIDs are valid.
    if [[ ! "$sid" =~ ^[0-9]+$ ]]; then
        echo "WARNING: Ignoring invalid SID entry: $sid"
        continue
    fi

    audit_engine "$sid" "Suricata" "$SURICATA_RULES_DIR" "suricata"
    audit_engine "$sid" "ICAPSuricata" "$ICAP_RULES_DIR" "icap"

done < "$EXCLUSIONS_FILE"

echo "=============================================================================================="
echo "Exclusion audit completed."
echo "Shared exclusions: $EXCLUSIONS_FILE"
echo "=============================================================================================="
