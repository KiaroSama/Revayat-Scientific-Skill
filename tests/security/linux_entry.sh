#!/bin/sh
set -eu
umask 077
mkdir -p /scratch/home /scratch/tmp /scratch/cache /scratch/work
cd /scratch/work
# Drop image defaults as well as host values before the trusted preflight.
exec env -i PATH=/opt/security-python/bin:/usr/bin:/bin \
    HOME=/scratch/home TMPDIR=/scratch/tmp XDG_CACHE_HOME=/scratch/cache \
    PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 REVAYAT_SECURITY_TIER=linux \
    /usr/bin/timeout --signal=TERM --kill-after=2s 90s \
    /opt/security-python/bin/python -B /opt/security/linux_probe.py --worker
