```markdown
# Privacy-First-Log-Clusterer

A standalone Python tool to cluster millions of log lines AND automatically sanitize (censor) sensitive PII data. Built for SREs, DevOps, and Security teams who need to reduce noise and stay compliant.

---

## Table of Contents

- [Features](#features)
- [Quickstart](#quickstart)
- [CLI Reference](#cli-reference)
- [Example Outputs](#example-outputs)
- [Security & Privacy](#security--privacy)
- [Troubleshooting & Tuning](#troubleshooting--tuning)
- [Contributing](#contributing)

---

## Features

- **Semantic Clustering:** Groups similar logs (SimHash 64-bit + Hamming distance).
- **PII Detection & Censoring:** Finds and masks emails, IPs, UUIDs, credit cards, etc.
- **Zero-Dependency:** A single log_clusterer.py file. No pip install. Copy it to a server and it just works (Python 3.8+).
- **HTML Report:** Generates a simple report.html you can share.
- **Audit Registry (JSON):** Exports a registry.json that proves PII was found and handled.
- **Live "Watch" Mode:** Can monitor a file in real-time (`--watch`).

---

## Quickstart

```shell
# Run the built-in demo (the best way to see it)
python log_clusterer.py --input demo --out demo_report.html --sanitize --export-registry registry.json

# Basic scan of a file (uncensored report)
python log_clusterer.py --input /var/log/app.log --out app_report.html

# The recommended "Privacy-First" run:
python log_clusterer.py \
    --input /var/log/app.log \
    --out app_report.html \
    --export-registry audit.json \
    --sanitize

# Live "watch" mode (monitors a file)
python log_clusterer.py --input /var/log/app.log --watch --sanitize
```

---

## CLI Reference

| Option             | Description                                                      | Default            |
|--------------------|------------------------------------------------------------------|--------------------|
| `--input`          | Path to log file (or `demo`)                                     | (required)         |
| `--out`            | Output HTML report path                                          | report.html        |
| `--sanitize`       | Censors PII (emails, IPs, etc.) in all reports                  | off                |
| `--export-registry`| Exports a `registry.json` for auditing                          | off                |
| `--threshold N`    | Similarity threshold (lower is stricter)                        | 6                  |
| `--watch`          | Monitors a file in real-time                                    | off                |

---

## Example Outputs

### registry.json (sample)
```json
{
  "run_id": "2025-10-30T12:00:00Z-abcdef",
  "sanitized": true,
  "detections": [
    {
      "pii_type": "email",
      "masked_value": "<EMAIL>",
      "sample_context": "User login failed for john.doe@email.com"
    },
    {
      "pii_type": "ipv4",
      "masked_value": "<IP>",
      "sample_context": "Connection from 203.0.113.42"
    }
  ],
  "summary": {
    "total_lines": 1000000,
    "clusters": 10,
    "total_pii_detections": 42
  }
}
```

### HTML Report (snippet)
> Example: Top Cluster —  
> `Failed login for <EMAIL> from <IP> at 2025-10-29 22:24:01`  
> Count: 450, PII flagged: email, ip

---

## Security & Privacy

- Treat `registry.json` as sensitive: it contains PII evidence and context. **Restrict file permissions!**
- Use `--sanitize` for all reports you plan to share or store.
- Avoid exporting registry files unless needed for compliance/audit.
- The tool does not store original raw PII values in outputs when `--sanitize` is enabled.

---

## Troubleshooting & Tuning

- **Too many clusters?** Increase `--threshold`.
- **Clusters too broad?** Lower `--threshold`.
- **Too many false PII detections?** Review log format and consider custom regexes.
- **Performance:** For very large files, run on a machine with ample RAM.

---

## Contributing

Feedback, bugs, and feature requests are welcome! Please open an issue or pull request on GitHub.

---

This code is released under a "Source Available" model (see LICENSE for details).
```
