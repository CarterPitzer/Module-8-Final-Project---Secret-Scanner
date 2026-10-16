import argparse
import logging
import os
from pathlib import Path
from patterns import PATTERNS

def configure_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")

def parse_args():
    parser = argparse.ArgumentParser(description="Scan files or directories for hardcoded secrets using regex patterns.")
    parser.add_argument("path")
    parser.add_argument("-r", "--recursive", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--extensions", nargs="*", default=[".py", ".txt", ".env", ".json", ".yaml", ".yml"])
    return parser.parse_args()

def iter_files(path, recursive, extensions):
    if path.is_file():
        yield path
        return
    if path.is_dir():
        if recursive:
            for root, _, files in os.walk(path):
                for name in files:
                    p = Path(root) / name
                    if not extensions or p.suffix in extensions:
                        yield p
        else:
            for p in path.iterdir():
                if p.is_file() and (not extensions or p.suffix in extensions):
                    yield p

def scan_file(path):
    findings = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for pattern in PATTERNS:
                    match = pattern["regex"].search(line)
                    if match:
                        findings.append({
                            "file": str(path),
                            "line": lineno,
                            "pattern_id": pattern["id"],
                            "description": pattern["description"],
                            "match": match.group(0)
                        })
    except Exception as e:
        logging.error("Failed to read %s: %s", path, e)
    return findings

def main():
    args = parse_args()
    configure_logging(args.verbose)
    target = Path(args.path)
    all_findings = []
    for file_path in iter_files(target, args.recursive, args.extensions):
        findings = scan_file(file_path)
        all_findings.extend(findings)
    if not all_findings:
        print("No potential secrets found.")
        return
    print("Potential secrets detected:")
    for f in all_findings:
        print(f"{f['file']}:{f['line']} [{f['pattern_id']} - {f['description']}] -> {f['match']}")

if __name__ == "__main__":
    main()
