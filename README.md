# Privacy-First-Log-Clusterer
A standalone Python tool to cluster millions of log lines AND automatically sanitize (censor) sensitive PII data.  Built for SREs, DevOps, and Security teams who need to reduce noise and stay compliant (GDPR/CCPA).
Log tools are good at sorting. But they let danger through: emails, credit card numbers, IP addresses. If an engineer shares one of those logs on Slack, it's a compliance violation that can cost millions.

This tool does both jobs in one pass:

It Sorts (The "Clusterer"): It reads 1 million log lines and groups them into 10 unique "problems".

It Censors (The "Sanitizer"): It finds john.doe@email.com and replaces it with <EMAIL>.

🧠 Key Features
Semantic Clustering: Groups similar logs (SimHash 64-bit + Hamming distance).

PII Detection & Censoring: Finds and masks emails, IPs, UUIDs, credit cards, etc.

Zero-Dependency: A single log_clusterer.py file. No pip install. Copy it to a server and it just works.

HTML Report: Generates a simple report.html you can share.

Audit Registry (JSON): Exports a registry.json that proves PII was found and handled.

Live "Watch" Mode: Can monitor a file in real-time (--watch).

🛠️ Quickstart (The Manual)
No installation needed. Just Python 3.8+.




# 1. Download (or clone) the script
git clone https://github.com/[GoldenSoldierQC/log-censor.git
cd log-censor

# 2. Run the built-in demo (the best way to see it)
python log_clusterer.py --input demo --out demo_report.html --sanitize --export-registry registry.json

# Basic scan of a file (uncensored report)
python log_clusterer.py --input /var/log/app.log --out app_report.html

# The recommended "Privacy-First" run:
# Sorts, Censors, AND creates an audit trail
python log_clusterer.py \
    --input /var/log/app.log \
    --out app_report.html \
    --export-registry audit.json \
    --sanitize

# Live "watch" mode (monitors a file)
python log_clusterer.py --input /var/log/app.log --watch --sanitize

# --- Key Options ---

--sanitize          # Censors PII (emails, IPs, etc.) in all reports
--export-registry   # Exports a 'registry.json' for auditing
--threshold N       # Similarity threshold (default: 6). Lower to be stricter.
