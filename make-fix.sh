#!/bin/bash
# Builds linux-host-fix.sh: the read-only audit plus the fix modules, as one file.
cd "$(dirname "$0")" || exit 1
{
    sed '/^main "\$@"$/d' linux-host-audit.sh
    cat fix/*.sh
    printf '\nfix_main "$@"\n'
} > linux-host-fix.sh
chmod +x linux-host-fix.sh
bash -n linux-host-fix.sh && wc -lc linux-host-fix.sh
