#!/usr/bin/env python3
"""
bazaar.py — Fetch APK samples from MalwareBazaar and scan with androidzip.

Usage:
    python3 bazaar.py [--limit N] [--tag TAG] [--json] [--bin PATH]
                      [--config PATH]

Exit codes:
    0  all samples clean (or no samples returned)
    1  script error (network, extraction, binary not found)
    2  one or more samples had malformations
"""

import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

try:
    import pyzipper
    _PYZIPPER = True
except ImportError:
    _PYZIPPER = False

API_URL = "https://mb-api.abuse.ch/api/v1/"


def load_api_key(config_path: str) -> str | None:
    """Parse api_key from a minimal YAML config without external dependencies."""
    try:
        with open(config_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("api_key:"):
                    value = line.split(":", 1)[1].strip().strip("\"'")
                    return value or None
    except FileNotFoundError:
        pass
    return None


def api_post(payload: dict, api_key: str | None) -> dict:
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(API_URL, data=data, method="POST")
    req.add_header("User-Agent", "androidzip-bazaar-scanner/1.0")
    if api_key:
        req.add_header("Auth-Key", api_key)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def query_samples(limit: int, tag: str | None, api_key: str | None) -> list[dict]:
    if tag:
        result = api_post({"query": "get_taginfo", "tag": tag, "limit": limit}, api_key)
    else:
        result = api_post({"query": "get_file_type", "file_type": "apk", "limit": limit}, api_key)

    status = result.get("query_status", "unknown")
    if status not in ("ok", "no_results"):
        raise RuntimeError(f"MalwareBazaar query_status: {status}")

    return result.get("data") or []


def download_zip(sha256: str, api_key: str | None) -> bytes:
    """Download the password-protected sample ZIP for the given SHA-256."""
    payload = {"query": "get_file", "sha256_hash": sha256}
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(API_URL, data=data, method="POST")
    req.add_header("User-Agent", "androidzip-bazaar-scanner/1.0")
    if api_key:
        req.add_header("Auth-Key", api_key)
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read()
    # MalwareBazaar incorrectly sends Content-Type: application/json even for
    # binary ZIP downloads. Detect by actual content: ZIP magic is b"PK\x03\x04".
    if body[:4] == b"PK\x03\x04":
        return body
    try:
        msg = json.loads(body).get("query_status", "unknown")
    except Exception:
        msg = "unreadable response"
    raise RuntimeError(f"download failed: {msg}")


def extract_apk(zip_bytes: bytes, dest_dir: str) -> str | None:
    """Extract the APK from the MalwareBazaar AES-256 password-protected ZIP."""
    # MalwareBazaar uses AES-256 encryption; pyzipper handles it.
    # Fall back to stdlib zipfile (ZipCrypto only) if pyzipper is absent.
    if not _PYZIPPER:
        raise RuntimeError("pyzipper required for AES-256 ZIPs: pip install pyzipper")
    with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()
        apk_names = [n for n in names if n.lower().endswith(".apk")]
        targets = apk_names or names
        if not targets:
            return None
        name = targets[0]
        zf.extract(name, path=dest_dir, pwd=b"infected")
        return os.path.join(dest_dir, name)


def scan(apk_path: str, binary: str, as_json: bool) -> tuple[int, str]:
    cmd = [binary]
    if as_json:
        cmd.append("--json")
    cmd.append(apk_path)
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout
    if result.stderr:
        output += result.stderr
    return result.returncode, output


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(
        description="Fetch APKs from MalwareBazaar and scan with androidzip."
    )
    parser.add_argument("--limit", type=int, default=10,
                        help="number of samples to fetch (default: 10)")
    parser.add_argument("--tag", default=None,
                        help="filter by MalwareBazaar tag (e.g. 'banker', 'rat')")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="emit JSON reports instead of human-readable text")
    parser.add_argument("--bin", default=os.path.join(script_dir, "androidzip"),
                        help="path to the androidzip binary (default: ./androidzip)")
    parser.add_argument("--config", default=os.path.join(script_dir, "config.yaml"),
                        help="YAML config with bazaar.api_key (default: config.yaml)")
    args = parser.parse_args()

    api_key = load_api_key(args.config)
    if api_key:
        eprint(f"API key loaded from {args.config}")
    else:
        eprint(f"No API key found in {args.config}, proceeding unauthenticated.")

    # Verify the binary is reachable before fetching any samples.
    if not (os.path.isfile(args.bin) or any(
        os.path.isfile(os.path.join(d, args.bin))
        for d in os.environ.get("PATH", "").split(os.pathsep)
    )):
        eprint(f"error: binary not found: {args.bin!r}  (build with 'make')")
        sys.exit(1)

    eprint(f"Querying MalwareBazaar for up to {args.limit} APK samples"
           + (f" tagged '{args.tag}'" if args.tag else "") + " …")

    try:
        samples = query_samples(args.limit, args.tag, api_key)
    except Exception as exc:
        eprint(f"error: {exc}")
        sys.exit(1)

    if not samples:
        eprint("No samples returned.")
        sys.exit(0)

    eprint(f"Got {len(samples)} sample(s).\n")

    malformed = 0
    errors = 0

    for i, sample in enumerate(samples, 1):
        sha256 = sample["sha256_hash"]
        file_name = sample.get("file_name") or (sha256 + ".apk")
        tags = ", ".join(sample.get("tags") or []) or "none"

        eprint(f"[{i}/{len(samples)}] {file_name}")
        eprint(f"          sha256={sha256}")
        eprint(f"          tags={tags}")

        try:
            eprint("          downloading …", end=" ", flush=True)
            zip_bytes = download_zip(sha256, api_key)
            eprint(f"{len(zip_bytes):,} bytes")
        except Exception as exc:
            eprint(f"\n          skip: {exc}")
            errors += 1
            continue

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                apk_path = extract_apk(zip_bytes, tmpdir)
            except Exception as exc:
                eprint(f"          skip: extraction failed: {exc}")
                errors += 1
                continue

            if not apk_path:
                eprint("          skip: no APK found inside ZIP")
                errors += 1
                continue

            rc, output = scan(apk_path, args.bin, args.as_json)

        if output:
            print(output, end="" if output.endswith("\n") else "\n")

        if rc == 2:
            malformed += 1
        elif rc != 0:
            eprint(f"          androidzip exited {rc}")
            errors += 1

    eprint("─" * 72)
    eprint(f"Done. {malformed}/{len(samples)} malformed, {errors} skipped.")
    sys.exit(0 if malformed == 0 else 2)


if __name__ == "__main__":
    main()
