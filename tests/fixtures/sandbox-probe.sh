#!/bin/bash
# Harmless observations of the production sandbox, not a comprehensive audit.
set -euo pipefail
fail() { printf 'sandbox-probe: %s\n' "$1" >&2; exit 1; }
[[ $(cat /input/sentinel.txt) == 'public sandbox fixture' ]] || fail input-read
if printf 'changed' >> /input/sentinel.txt 2>/dev/null; then fail input-write; fi
awk '$2 == "/input" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit !found }' /proc/mounts || fail input-mount
awk '$2 == "/" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit !found }' /proc/mounts || fail root-mount
[[ -r /usr/bin/timeout ]] || fail toolchain-read
if printf 'probe' > /usr/local/bin/revayat-probe-write 2>/dev/null; then fail toolchain-write; fi
printf 'allowed output\n' > /output/probe.txt
printf 'allowed temporary\n' > /tmp/probe.txt
[[ -z ${REVAYAT_HOST_ONLY_CANARY+x} ]] || fail environment-leak
[[ $HOME == /tmp/tex-home ]] || fail scratch-home
[[ $(id -u) != 0 ]] || fail root-user
awk '$1 == "CapEff:" || $1 == "CapBnd:" { if ($2 != "0000000000000000") exit 1; n++ } END { if (n != 2) exit 1 }' /proc/self/status || fail capabilities
awk '$1 == "NoNewPrivs:" { if ($2 != 1) exit 1; found=1 } END { if (!found) exit 1 }' /proc/self/status || fail privilege-escalation
[[ $(cat /sys/fs/cgroup/memory.max) == 1073741824 ]] || fail memory-limit
[[ $(cat /sys/fs/cgroup/pids.max) == 64 ]] || fail process-limit
read -r quota period < /sys/fs/cgroup/cpu.max
[[ $quota != max && $quota -eq $((2 * period)) ]] || fail cpu-limit
[[ $(ulimit -f) == 262144 ]] || fail file-size-limit
[[ $(ulimit -n) == 128 ]] || fail file-descriptor-limit
[[ $(df -Pk /tmp | awk 'NR == 2 { print $2 }') == 262144 ]] || fail temporary-disk-limit
for interface in /sys/class/net/*; do
    [[ ${interface##*/} == lo ]] || fail external-interface
done
awk 'NR > 1 && $1 != "lo" { exit 1 }' /proc/net/route || fail external-route
# TEST-NET-1 is not a deployed endpoint; no route must exist before this attempt.
if timeout --signal=TERM --kill-after=1s 2s bash -c 'exec 3<>/dev/tcp/192.0.2.1/9' 2>/dev/null; then
    fail network-connect
fi
printf 'sandbox-probe: readonly network environment privilege resources scratch passed\n'
