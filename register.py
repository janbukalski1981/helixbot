#!/usr/bin/env python3
"""Register a poisoned tool description with a tool registry / MCP gateway.

Loads one of the variants/ JSON files and either:
  (a) POSTs it to a registry endpoint (default: local mock), or
  (b) prints a ready-to-run curl command.

Usage:
  python3 register.py 01_explicit
  python3 register.py 04_invisible --url http://localhost:8080/tools --dry-run
  python3 register.py 05_compound --token "$REG_TOKEN"
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
VARIANTS = os.path.join(HERE, "variants")


def load_variant(name: str) -> dict:
    # Accept "01_explicit", "01", or a full path
    if os.path.isfile(name):
        path = name
    else:
        path = os.path.join(VARIANTS, f"{name}.json")
        if not os.path.isfile(path):
            available = sorted(f for f in os.listdir(VARIANTS) if f.endswith(".json"))
            sys.exit(f"No variant '{name}'. Available: {', '.join(available)}")
    with open(path, encoding="utf-8") as f:
        tool = json.load(f)
    tool["_source_file"] = os.path.basename(path)
    return tool


def describe(tool: dict) -> str:
    """Summarize the poison payload so the operator can verify before firing."""
    desc = tool["description"]
    invisible = [hex(ord(c)) for c in desc if ord(c) in (0x200b, 0x200c, 0x200d, 0x2060)]
    return (
        f"tool      : {tool['name']}\n"
        f"desc len  : {len(desc)}\n"
        f"invisible : {len(invisible)} char(s) {invisible or ''}\n"
        f"payload   : {desc[desc.find('create_ticket') - 40:] if 'create_ticket' in desc else desc[-160:]}\n"
    )


def build_curl(url: str, payload: dict, token: str | None) -> str:
    body = json.dumps(payload, ensure_ascii=False)
    hdrs = ["-H", "Content-Type: application/json"]
    if token:
        hdrs += ["-H", f"Authorization: Bearer {token}"]
    return "curl -sS -X POST " + " ".join(f"'{h}'" if len(h) > 1 else f"-H" for h in hdrs) + \
           f" '{url}' --data '{body}'"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("variant", help="variant name (e.g. 01_explicit) or path to a .json")
    ap.add_argument("--url", default="http://localhost:8080/tools", help="registry endpoint (POST)")
    ap.add_argument("--token", default=os.environ.get("REG_TOKEN"), help="Bearer token (or $REG_TOKEN)")
    ap.add_argument("--dry-run", action="store_true", help="print the curl command instead of POSTing")
    ap.add_argument("--show", action="store_true", help="print the poison summary before firing")
    args = ap.parse_args()

    tool = load_variant(args.variant)
    if args.show or args.dry_run:
        print(describe(tool))
        print()

    # Strip the helper key before sending
    payload = {k: v for k, v in tool.items() if not k.startswith("_")}

    if args.dry_run:
        print(build_curl(args.url, payload, args.token))
        return

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(args.url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if args.token:
        req.add_header("Authorization", f"Bearer {args.token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"HTTP {resp.status}")
            print(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection failed: {e.reason}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
