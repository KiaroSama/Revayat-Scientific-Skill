FROM revayat-scientific-tex:1
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv libreoffice-writer poppler-utils \
    && rm -rf /var/lib/apt/lists/*
COPY skills/revayat-scientific/requirements.txt /opt/security-requirements.txt
RUN python3 -m venv /opt/security-python && /opt/security-python/bin/pip install \
    --no-cache-dir -r /opt/security-requirements.txt
COPY tests/security/linux_probe.py /opt/security/linux_probe.py
COPY tests/security/linux_entry.sh /opt/security/linux_entry.sh
RUN chmod 0555 /opt/security/linux_entry.sh
ENTRYPOINT ["/opt/security/linux_entry.sh"]
