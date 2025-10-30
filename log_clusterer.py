#!/usr/bin/env python3
import argparse
import os
import re
import time
import json
import html
import hashlib
from collections import defaultdict
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time as _time

# ---------------- Registry types (inspiré de la suggestion Copilot) ----------------

class MediaType:
    IMAGE = "image"
    TEXT = "text"
    AUDIO = "audio"
    VIDEO = "video"
    OTHER = "other"

@dataclass
class LicenseInfo:
    name: str             # ex.: "CC-BY-4.0", "Internal-Restricted"
    uri: Optional[str] = None
    allows_derivatives: bool = False
    requires_attribution: bool = True
    commercial_use_allowed: bool = False

@dataclass
class ConsentRecord:
    subject_id: str         # ex.: "service-audit-log", "user-data" (what the consent is about)
    granted_by: str         # ex.: propriétaire des droits / équipe
    scope: List[str] = field(default_factory=list)  # ex.: ["storage","distribution"]
    timestamp: float = field(default_factory=lambda: _time.time())
    expires_at: Optional[float] = None

@dataclass
class Artifact:
    artifact_id: str
    path: str
    media_type: str
    metadata: Dict[str, str]
    license: LicenseInfo
    consent: Optional[ConsentRecord] = None

# ---------------- SimHash utilities ----------------

SIMHASH_BITS = 64
_token_split_re = re.compile(r"\w+", re.UNICODE)

def tokenize(text, use_bigrams=True):
    toks = _token_split_re.findall(text.lower())
    if not use_bigrams:
        return toks
    bigrams = [f"{toks[i]}_{toks[i+1]}" for i in range(len(toks)-1)] if len(toks) > 1 else []
    return toks + bigrams


def stable_hash64(token: str) -> int:
    h = hashlib.md5(token.encode('utf8')).digest()
    hi = int.from_bytes(h[:8], 'big')
    lo = int.from_bytes(h[8:], 'big')
    return (hi ^ lo) & ((1 << SIMHASH_BITS) - 1)


def simhash(text: str, use_bigrams=True) -> int:
    toks = tokenize(text, use_bigrams=use_bigrams)
    if not toks:
        return 0
    freqs = defaultdict(int)
    for t in toks:
        freqs[t] += 1
    vec = [0] * SIMHASH_BITS
    for token, w in freqs.items():
        h = stable_hash64(token)
        for i in range(SIMHASH_BITS):
            bit = (h >> i) & 1
            vec[i] += (1 if bit else -1) * w
    fp = 0
    for i in range(SIMHASH_BITS):
        if vec[i] > 0:
            fp |= (1 << i)
    return fp


def hamming(a: int, b: int) -> int:
    x = a ^ b
    try:
        # Python 3.8+
        return x.bit_count()
    except AttributeError:
        # Fallback for older Python versions
        return bin(x).count("1")

# ---------------- Simple PII detection / sanitization ----------------

PII_PATTERNS = {
    'email': re.compile(r"[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,6}"),
    'ipv4': re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    'credit_card_like': re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    'uuid': re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    'phone': re.compile(r"\+?\d[\d \-()]{7,}\d"),
}


def detect_pii(text: str) -> Dict[str, List[str]]:
    found = {}
    for k, pat in PII_PATTERNS.items():
        m = pat.findall(text)
        if m:
            # normalize small set
            found[k] = list(dict.fromkeys(m))
    return found


def sanitize_text(text: str) -> str:
    # Replace any PII with placeholders
    out = text
    for k, pat in PII_PATTERNS.items():
        out = pat.sub(f"<{k.upper()}>", out)
    return out

# ---------------- Clustering primitives ----------------

class Cluster:
    def __init__(self, first_msg, first_ts, fp):
        self.count = 1
        self.messages = [first_msg]
        self.first_ts = first_ts
        self.last_ts = first_ts
        self.fingerprints = [fp]
        self.bit_counts = [0] * SIMHASH_BITS
        for i in range(SIMHASH_BITS):
            if (fp >> i) & 1:
                self.bit_counts[i] = 1
        self.centroid = fp

    def add(self, msg, ts, fp):
        self.count += 1
        if len(self.messages) < 8:
            self.messages.append(msg)
        else:
            self.messages.pop(0)
            self.messages.append(msg)
        self.last_ts = ts
        self.fingerprints.append(fp)
        for i in range(SIMHASH_BITS):
            if (fp >> i) & 1:
                self.bit_counts[i] += 1
        half = (self.count / 2.0)
        centroid = 0
        for i in range(SIMHASH_BITS):
            if self.bit_counts[i] > half:
                centroid |= (1 << i)
        self.centroid = centroid

    def representative(self):
        return self.messages[-1] if self.messages else ""

# ---------------- Log parsing / timestamp extraction ----------------

TIMESTAMP_PATTERNS = [
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)",
    r"(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
    r"(?P<ts>\d{2}:\d{2}:\d{2})",
    r"(?P<ts>\d{10})",
]
compiled_ts = [re.compile(p) for p in TIMESTAMP_PATTERNS]


def extract_timestamp(line: str):
    for cre in compiled_ts:
        m = cre.search(line)
        if m:
            s = m.group('ts')
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%H:%M:%S"):
                try:
                    dt = datetime.strptime(s, fmt)
                    if fmt == "%H:%M:%S":
                        dt = datetime.combine(datetime.today().date(), dt.time())
                    return dt
                except Exception:
                    pass
            if re.fullmatch(r"\d{10}", s):
                return datetime.fromtimestamp(int(s))
    return None

# ---------------- Report generation (FIXED) ----------------

# *** LA CORRECTION EST ICI ***
# On doit "doubler" les accolades du CSS ( { -> {{ ) pour que .format() les ignore.
REPORT_TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Log Cluster Report</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,Arial;margin:20px}}
.card{{border:1px solid #eee;padding:12px;margin-bottom:10px;border-radius:8px}}
.h{{font-size:18px;margin-bottom:6px}}
.small{{font-size:12px;color:#666}}
.bar{{height:12px;background:#444;border-radius:6px}}
</style>
</head>
<body>
<h1>Rapport de clustering — {title}</h1>
<p class="small">Généré: {generated}</p>
<p class="small">Nombre de clusters: {n_clusters} — total events: {n_events}</p>
{clusters_html}
</body>
</html>
"""


def generate_clusters_html(clusters, sanitize=False):
    parts = []
    sorted_c = sorted(clusters, key=lambda c: c.count, reverse=True)
    for idx, c in enumerate(sorted_c, 1):
        age = f"{(datetime.now() - c.last_ts).total_seconds():.0f}s" if isinstance(c.last_ts, datetime) else str(c.last_ts)
        examples = [sanitize_text(m) if sanitize else m for m in c.messages]
        sample = "<br>".join(html.escape(m) for m in examples)
        parts.append(f"<div class=\"card\">\n  <div class=\"h\">Cluster #{idx} — {c.count} occurrences</div>\n  <div class=\"small\">First: {html.escape(str(c.first_ts))} — Last: {html.escape(str(c.last_ts))} — âge: {age}</div>\n  <div style=\"margin-top:8px\">Exemples:<br>{sample}</div>\n</div>")
    return "\n".join(parts)

# ---------------- Main processing ----------------

class LogClusterer:
    def __init__(self, hamming_threshold=6, watch=False, report_path='report.html', poll_interval=1.0, sanitize=False):
        self.hamming_threshold = hamming_threshold
        self.watch = watch
        self.report_path = report_path
        self.poll_interval = poll_interval
        self.clusters: List[Cluster] = []
        self.total_events = 0
        self.sanitize = sanitize

    def process_line(self, line):
        ts = extract_timestamp(line)
        if ts is None:
            ts = datetime.now()
        cleaned = re.sub(r"^.*?\]\s*", "", line).strip()
        fp = simhash(cleaned)
        best = None
        best_d = SIMHASH_BITS + 1
        for c in self.clusters:
            d = hamming(fp, c.centroid)
            if d < best_d:
                best = c
                best_d = d
        if best is None or best_d > self.hamming_threshold:
            newc = Cluster(cleaned, ts, fp)
            self.clusters.append(newc)
        else:
            best.add(cleaned, ts, fp)
        self.total_events += 1

    def process_file(self, path):
        if os.path.isdir(path):
            for fname in sorted(os.listdir(path)):
                full = os.path.join(path, fname)
                if os.path.isfile(full):
                    self._process_file_once(full)
        else:
            self._process_file_once(path)

    def _process_file_once(self, filepath):
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                self.process_line(line)

    def watch_file(self, path):
        if os.path.isdir(path):
            known_sizes = {}
            while True:
                for fname in sorted(os.listdir(path)):
                    full = os.path.join(path, fname)
                    if not os.path.isfile(full):
                        continue
                    size = os.path.getsize(full)
                    prev = known_sizes.get(full, 0)
                    if size < prev:
                        prev = 0
                    if size > prev:
                        with open(full, 'r', errors='ignore') as f:
                            f.seek(prev)
                            for line in f:
                                self.process_line(line.strip())
                    known_sizes[full] = size
                self.write_report()
                time.sleep(self.poll_interval)
        else:
            with open(path, 'r', errors='ignore') as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        self.write_report()
                        time.sleep(self.poll_interval)
                        continue
                    self.process_line(line.strip())

    def clusters_to_registry(self, out_path: str, sanitized: bool = False):
        registry = []
        for i, c in enumerate(sorted(self.clusters, key=lambda x: x.count, reverse=True), 1):
            rep = c.representative()
            pii = detect_pii(rep)
            rep_out = sanitize_text(rep) if sanitized else rep
            artifact = Artifact(
                artifact_id=f"cluster-{i}-{abs(hash(c.centroid))% (10**8)}",
                path=out_path,
                media_type=MediaType.TEXT if 'MediaType' in globals() else 'text',
                metadata={
                    'count': str(c.count),
                    'first_ts': str(c.first_ts),
                    'last_ts': str(c.last_ts),
                    'representative': rep_out,
                    'pii_detected': json.dumps(pii),
                },
                license=LicenseInfo(name='Internal-Restricted', requires_attribution=False, commercial_use_allowed=False),
                consent=None,
            )
            # convert dataclass-like to dict (simple)
            registry.append({
                'artifact_id': artifact.artifact_id,
                'path': artifact.path,
                'media_type': artifact.media_type,
                'metadata': artifact.metadata,
                'license': {
                    'name': artifact.license.name,
                    'uri': artifact.license.uri,
                    'allows_derivatives': artifact.license.allows_derivatives,
                    'requires_attribution': artifact.license.requires_attribution,
                    'commercial_use_allowed': artifact.license.commercial_use_allowed,
                },
                'consent': None,
            })
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump({'generated': datetime.now().isoformat(), 'registry': registry}, f, indent=2, ensure_ascii=False)

    def write_report(self, title=None, registry_path: Optional[str] = None):
        title = title or os.path.basename(self.report_path)
        clusters_html = generate_clusters_html(self.clusters, sanitize=self.sanitize)
        html_text = REPORT_TEMPLATE.format(title=html.escape(title), generated=datetime.now().isoformat(), n_clusters=len(self.clusters), n_events=self.total_events, clusters_html=clusters_html)
        with open(self.report_path, 'w', encoding='utf-8') as f:
            f.write(html_text)
        if registry_path:
            self.clusters_to_registry(registry_path, sanitized=self.sanitize)

# ---------------- CLI ----------------

def parse_args():
    p = argparse.ArgumentParser(description='Log clusterer: regroupe messages similaires et produit un rapport HTML + registry JSON')
    p.add_argument('--input', '-i', required=True, help='Fichier de log ou dossier à analyser (ou "demo")')
    p.add_argument('--out', '-o', default='log_report.html', help='Fichier HTML de sortie')
    p.add_argument('--watch', '-w', action='store_true', help='Mode watch (polling, suivi en temps réel)')
    p.add_argument('--threshold', '-t', type=int, default=6, help='Seuil de Hamming pour regrouper (par défaut 6)')
    p.add_argument('--poll', type=float, default=1.0, help='Intervalle de polling en secondes (pour --watch)')
    p.add_argument('--export-registry', help='Chemin JSON pour exporter le registry des clusters')
    p.add_argument('--sanitize', action='store_true', help='Sanitise (masque) les PII dans le rapport et le registry')
    return p.parse_args()


def demo_generate_sample_log(path, n=200):
    import random
    patterns = [
        'ERROR Database connection timeout to host db1:5432',
        'WARN Cache miss for key user:12345',
        'INFO User 42 logged in',
        'ERROR Failed to write to disk /mnt/data: no space left',
        'ERROR Unable to parse JSON payload: unexpected token',
        'CRITICAL Kernel panic - stack trace...',
        'WARN High memory usage: 85% on host web-02',
        'INFO Payment processed for card 4111 1111 1111 1111',
        'INFO User email john.doe@example.com created account',
    ]
    with open(path, 'w', encoding='utf-8') as f:
        for i in range(n):
            t = datetime.now().isoformat()
            line = f"{t} {random.choice(patterns)}\n"
            f.write(line)
            if i % 37 == 0:
                f.write(f"{t} ERROR Database connection timeout to host db2:5432\n")


if __name__ == '__main__':
    args = parse_args()
    lc = LogClusterer(hamming_threshold=args.threshold, watch=args.watch, report_path=args.out, poll_interval=args.poll, sanitize=args.sanitize)
    if args.input == 'demo':
        sample = 'sample_demo.log'
        demo_generate_sample_log(sample)
        lc.process_file(sample)
        lc.write_report(title='demo', registry_path=args.export_registry if args.export_registry else None)
        print(f"Demo report généré: {args.out} (ouvrir sample_demo.log et {args.out})")
        if args.export_registry:
            print(f"Registry exporté: {args.export_registry}")
    else:
        if args.watch:
            print(f"Watching {args.input} — rapport en live -> {args.out}")
            try:
                lc.watch_file(args.input)
            except KeyboardInterrupt:
                lc.write_report(registry_path=args.export_registry if args.export_registry else None)
                print("Arrêté. Rapport final écrit.")
        else:
            lc.process_file(args.input)
            lc.write_report(registry_path=args.export_registry if args.export_registry else None)
            print(f"Traitement terminé. Rapport: {args.out}")
            if args.export_registry:
                print(f"Registry exporté: {args.export_registry}")
