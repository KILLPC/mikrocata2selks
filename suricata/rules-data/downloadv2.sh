#!/bin/bash

wd="/opt/mikrocata2selks/suricata/rules-data"
ex_file="/opt/mikrocata2selks/suricata/rules-data/exclusions.txt"

# 1. Download and extract rulesets
sudo curl -Lo $wd/emerging.rules.tar.gz https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz
tar -xvf $wd/emerging.rules.tar.gz
sudo curl -Lo $wd/rules/sslblacklist.rules https://sslbl.abuse.ch/blacklist/sslblacklist.rules
sudo curl -Lo $wd/rules/ja3_fingerprints.rules https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules
sudo curl -Lo $wd/stamus-lateral.rules https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz
tar -xvf $wd/stamus-lateral.rules
sudo curl -Lo $wd/rules/antiphishing.rules https://raw.githubusercontent.com/julioliraup/Antiphishing/refs/heads/main/antiphishing.rules
sudo curl -Lo $wd/rules/etn_aggressive.rules https://security.etnetera.cz/feeds/etn_aggressive.rules
sudo curl -Lo $wd/rules/ids.rules https://urlhaus.abuse.ch/downloads/ids
sudo curl -Lo $wd/rules/ptopen.rules -A "Mozilla/5.0" https://rules.ptsecurity.com/files/ptopen-all.rules

# 2. Automatically comment out SIDs listed in exclusions.txt
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

# 3. Reload rules and rotate logs
docker exec suricata logrotate -vf /etc/logrotate.d/suricata
docker exec suricata suricatasc -c ruleset-reload-nonblocking
