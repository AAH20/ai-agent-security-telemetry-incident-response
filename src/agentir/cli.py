from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import detect, forensic_package, load_jsonl, load_rules
from .generators import generate_rules


def main() -> None:
    parser = argparse.ArgumentParser(prog="agentir", description="Detect and investigate AI agent and MCP security incidents")
    sub = parser.add_subparsers(dest="command", required=True)
    replay = sub.add_parser("replay")
    replay.add_argument("events", type=Path)
    replay.add_argument("--rules", type=Path, default=Path("detections/rules.json"))
    replay.add_argument("--output", type=Path)
    generate = sub.add_parser("generate")
    generate.add_argument("--rules", type=Path, default=Path("detections/rules.json"))
    generate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rules = load_rules(args.rules)
    if args.command == "generate":
        generate_rules(rules, args.output)
        print(f"generated {len(rules)} rules in {args.output}")
        return
    events = load_jsonl(args.events)
    findings = detect(events, rules)
    package = forensic_package(events, findings)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(package, indent=2) + "\n")
    print(json.dumps(package, indent=2))


if __name__ == "__main__":
    main()
