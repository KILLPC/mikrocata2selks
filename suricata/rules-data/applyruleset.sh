#!/bin/bash

wd="/opt/mikrocata2selks/suricata/rules-data"
wdicap="/opt/mikrocata2selks/icapsuricata/rules-data"
ex_file="/opt/mikrocata2selks/suricata/rules-data/exclusions.txt"
ex_file_icap="/opt/mikrocata2selks/suricata/rules-data/exclusions.txt"

# 1. Automatically comment out SIDs listed in exclusions.txt
if [ -f "$ex_file" ]; then
    echo "Applying rule exclusions from $ex_file..."
    while read -r sid; do
        # Skip empty lines or comment lines in exclusions.txt
        [[ -z "$sid" || "$sid" =~ ^# ]] && continue

        # Find active rules containing 'sid:XXXXX;' and prepend '#' if not already commented out
        find "$wd/rules" -name "*.rules" -type f -exec sed -i -E "s/^( *alert )(.*sid:$sid;)/#\1\2/" {} +
    done < "$ex_file"
    echo "Exclusions applied successfully."
fi

# Automatically comment out SIDs listed in exclusions.txt for icapsuricata
if [ -f "$ex_file_icap" ]; then
    echo "Applying rule exclusions from $ex_file_icap..."
    while read -r sid; do
        # Skip empty lines or comment lines in exclusions.txt
        [[ -z "$sid" || "$sid" =~ ^# ]] && continue

        # Find active rules containing 'sid:XXXXX;' and prepend '#' if not already commented out
        find "$wdicap/rules" -name "*.rules" -type f -exec sed -i -E "s/^( *alert )(.*sid:$sid;)/#\1\2/" {} +
    done < "$ex_file_icap"
    echo "Exclusions applied successfully."
fi

python3 $wdicap/convert_severity_to_drop.py \
--rules-dir="$wdicap/rules/" \
--classification="/opt/mikrocata2selks/icapsuricata/suricata-config/classification.config" \
--apply --severity 1 \
--protocol http \
--output-file="$wdicap/rules/filtered.rules" \
--force

# 3. Reload rules and rotate logs
docker exec suricata suricatasc -c ruleset-reload-nonblocking
docker exec icapsuricata suricatasc -c ruleset-reload-nonblocking
