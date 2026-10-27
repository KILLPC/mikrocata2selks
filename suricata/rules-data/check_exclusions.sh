#!/usr/bin/env bash

EXCLUSIONS_FILE="/opt/mikrocata2selks/suricata/rules-data/exclusions.txt"
RULES_DIR="/opt/mikrocata2selks/suricata/rules-data/rules"

if [[ ! -f "$EXCLUSIONS_FILE" ]]; then
    echo "Error: Exclusions file not found at $EXCLUSIONS_FILE"
    exit 1
fi

echo "================================================================================"
printf "%-10s | %-32s | %s\n" "SID" "FILE" "RULE MSG"
echo "================================================================================"

while IFS= read -r sid || [[ -n "$sid" ]]; do
    # Skip empty lines or comments in exclusions.txt
    [[ -z "$sid" || "$sid" =~ ^# ]] && continue
    
    # Strip any trailing carriage returns (\r)
    sid=$(echo "$sid" | tr -d '\r')

    # Search rules directory for the exact SID match
    match=$(grep -E -H "sid:${sid};" "$RULES_DIR"/*.rules 2>/dev/null)

    if [[ -n "$match" ]]; then
        filename=$(basename "${match%%:*}")
        msg=$(echo "$match" | grep -oP 'msg:"\K[^"]+')
        printf "%-10s | %-32s | %s\n" "$sid" "$filename" "$msg"
    else
        # Fallback to sid-msg.map if not found in active .rules files
        map_match=$(grep -E "^${sid} \|\|" "$RULES_DIR/sid-msg.map" 2>/dev/null)
        if [[ -n "$map_match" ]]; then
            msg=$(echo "$map_match" | awk -F '||' '{print $2}' | xargs)
            printf "%-10s | %-32s | %s\n" "$sid" "sid-msg.map" "$msg"
        else
            printf "%-10s | %-32s | %s\n" "$sid" "NOT FOUND" "-"
        fi
    fi
done < "$EXCLUSIONS_FILE"
