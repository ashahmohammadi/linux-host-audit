#!/bin/bash
# Builds paste-to-server.txt: the whole tool as one paste, for servers without internet access.
cd "$(dirname "$0")" || exit 1
{
    printf "base64 -d <<'LHA_END' | gunzip | bash\n"
    gzip -9c linux-host-audit.sh | base64 -w 76
    printf 'LHA_END\n'
} > paste-to-server.txt
wc -lc paste-to-server.txt
