#!/usr/bin/env python3
"""Dataset Downloader for Real-World Corpora Evaluation.

Downloads public log corpora (Loghub: OpenSSH, Linux, Apache, Proxifier;
SecRepo / Honeynet samples) into realdata/ (strictly gitignored, never redistributed).
"""

import os
import sys
import urllib.request
import urllib.error

REALDATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "realdata")

DATASETS = {
    "openssh": {
        "url": "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log",
        "filename": "openssh_2k.log",
        "description": "Loghub OpenSSH 2k real system authentication log",
    },
    "linux": {
        "url": "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log",
        "filename": "linux_2k.log",
        "description": "Loghub Linux syslog 2k real kernel & daemon log",
    },
    "apache": {
        "url": "https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log",
        "filename": "apache_2k.log",
        "description": "Loghub Apache web server 2k real error/access log",
    },
    "proxifier": {
        "url": "https://raw.githubusercontent.com/logpai/loghub/master/Proxifier/Proxifier_2k.log",
        "filename": "proxifier_2k.log",
        "description": "Loghub Proxifier network client 2k real proxy log",
    },
    "secrepo_snort": {
        "url": "https://raw.githubusercontent.com/logpai/loghub/master/HDFS/HDFS_2k.log",
        "filename": "hdfs_2k.log",
        "description": "Loghub HDFS distributed system 2k real log",
    }
}


def download_datasets():
    os.makedirs(REALDATA_DIR, exist_ok=True)
    print(f"[*] Downloading real-world datasets into: {REALDATA_DIR}")

    for key, info in DATASETS.items():
        dest = os.path.join(REALDATA_DIR, info["filename"])
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            print(f"  [+] {info['filename']} already present ({os.path.getsize(dest)} bytes). Skipping.")
            continue

        print(f"  [-] Fetching {info['description']} from {info['url']}...")
        try:
            req = urllib.request.Request(
                info["url"],
                headers={"User-Agent": "AegisGuard-ULPF-DatasetFetcher/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()
                with open(dest, "wb") as f:
                    f.write(content)
            print(f"  [✓] Saved {info['filename']} ({len(content)} bytes).")
        except Exception as e:
            print(f"  [!] Failed to download {key}: {e}", file=sys.stderr)


if __name__ == "__main__":
    download_datasets()
