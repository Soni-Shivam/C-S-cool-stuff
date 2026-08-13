#!/bin/bash
# GCE startup script for the DRISHTI extraction box (Box A).
# Installs the toolchain only. It deliberately does NOT auto-download malware —
# you SSH in and launch extraction yourself, so a misconfigured boot never starts
# pulling samples unattended.
set -euxo pipefail

apt-get update
apt-get install -y python3 python3-pip python3-venv git build-essential \
    libssl-dev libmagic1 curl

# Swap: guards against OOM on large packed multi-DEX samples.
if [ ! -f /swapfile ]; then
  fallocate -l 4G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

install -d -o ubuntu -g ubuntu /opt/drishti 2>/dev/null || install -d /opt/drishti
cd /opt/drishti

python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install androguard yara-python scikit-learn pandas numpy joblib \
    pydantic pydantic-settings cryptography google-genai

cat > /etc/profile.d/drishti.sh <<'EOF'
export DRISHTI_HOME=/opt/drishti
alias drishti-py='/opt/drishti/venv/bin/python'
echo "DRISHTI extractor ready."
echo "  1. Upload backend/ (scripts + drishti package) to /opt/drishti"
echo "  2. export ANDROZOO_API_KEY=\$(gcloud secrets versions access latest --secret=androzoo-key)"
echo "  3. drishti-py scripts/androzoo_extract.py samples.csv features.csv"
echo "  4. gcloud storage cp features.csv \$(curl -s -H Metadata-Flavor:Google \\"
echo "       http://metadata.google.internal/computeMetadata/v1/instance/attributes/out-bucket)/"
echo "SAFETY: this box must never EXECUTE an APK. Static parsing only."
EOF

echo "startup-script complete" > /var/log/drishti-ready
