#!/bin/bash
# BEGIN PER-SOURCE DOWNLOAD MODE
DOWNLOAD_ONLY=0
case "$#" in
    0)
        ;;
    1)
        if [[ "$1" != "0" ]]; then
            echo "Usage: $0 [0]  (0 = download only; no argument = download and apply)" >&2
            exit 64
        fi
        DOWNLOAD_ONLY=1
        ;;
    *)
        echo "Usage: $0 [0]  (0 = download only; no argument = download and apply)" >&2
        exit 64
        ;;
esac
# END PER-SOURCE DOWNLOAD MODE

wd="/opt/mikrocata2selks/suricata/rules-data"
wdicap="/opt/mikrocata2selks/icapsuricata/rules-data"
ex_file="/opt/mikrocata2selks/suricata/rules-data/exclusions.txt"
ex_file_icap="/opt/mikrocata2selks/suricata/rules-data/exclusions.txt"

# 1. Download and extract rulesets
sudo curl -Lo $wd/emerging.rules.tar.gz https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz
tar -xvf $wd/emerging.rules.tar.gz
sudo curl -Lo $wd/rules/sslblacklist.rules https://sslbl.abuse.ch/blacklist/sslblacklist.rules
sudo curl -Lo $wd/rules/ja3_fingerprints.rules https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules
sudo curl -Lo $wd/stamus-lateral.rules https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz
tar -xvf $wd/stamus-lateral.rules
sudo curl -Lo $wd/rules/antiphishing.rules https://raw.githubusercontent.com/julioliraup/Antiphishing/refs/heads/main/antiphishing.rules
sudo curl -Lo $wd/rules/etn_aggressive.rules https://security.etnetera.cz/feeds/etn_aggressive.rules
sudo curl -Lo $wd/rules/ids.rules https://urlhaus-api.abuse.ch/v2/files/exports/<auth key>/urlhaus_ids_suricata.rules
sudo curl -Lo $wd/rules/ptopen.rules -A "Mozilla/5.0" https://rules.ptsecurity.com/files/ptopen-all.rules

# BEGIN PER-SOURCE DOWNLOAD/APPLY SPLIT
# 2. Apply the downloaded rulesets (unless explicitly requested download-only)
if [[ "$DOWNLOAD_ONLY" -eq 1 ]]; then
    echo "Download complete. Apply and post-apply log rotation skipped (download-only mode)."
else
    bash "$wd/applyruleset.sh"

    # 3. Rotate logs after the normal apply/reload operation
    docker exec suricata logrotate -vf /etc/logrotate.d/suricata
    docker exec icapsuricata logrotate -vf /etc/logrotate.d/suricata
fi
# END PER-SOURCE DOWNLOAD/APPLY SPLIT
