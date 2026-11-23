#!/usr/bin/env python3
"""Threat Hunting Platform - safe local demo.

Runs hypothesis-driven hunts over synthetic endpoint telemetry,
matches IOCs, and reports Confirmed / Partial / No evidence per hunt.
Standard library only. No network, no live endpoints.
"""
import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_hunt(hunt, events, iocs):
    field, value = hunt["field"], hunt["value"].lower()
    matches = [e for e in events if value in str(e.get(field, "")).lower()]
    # IOC cross-check: flag matches that also hit a known IOC.
    ioc_hits = []
    for e in matches:
        for kind, values in iocs.items():
            for v in values:
                if v.lower() in json.dumps(e).lower():
                    ioc_hits.append({"event": e, "ioc_type": kind, "ioc": v})
    verdict = "Confirmed" if len(matches) >= 2 else "Partial" if len(matches) == 1 else "No evidence"
    return {"id": hunt["id"], "hunt": hunt["name"], "hypothesis": hunt["hypothesis"],
            "mitre_tactic": hunt["mitre_tactic"], "mitre_technique": hunt["mitre_technique"],
            "verdict": verdict, "match_count": len(matches), "ioc_hits": len(ioc_hits),
            "evidence": matches}


def main():
    p = argparse.ArgumentParser(description="Threat Hunting Platform (demo)")
    p.add_argument("--events", default=os.path.join(HERE, "..", "demo_data", "endpoint_events.json"))
    p.add_argument("--iocs", default=os.path.join(HERE, "..", "demo_data", "iocs.json"))
    p.add_argument("--out", default=os.path.join(HERE, "..", "out", "findings.json"))
    args = p.parse_args()

    events = load_json(args.events)
    iocs = load_json(args.iocs)
    hunts = load_json(os.path.join(HERE, "hunts.json"))
    results = [run_hunt(h, events, iocs) for h in hunts]

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"events_scanned": len(events), "hunts_run": len(results), "results": results}, f, indent=2)

    print(f"Events scanned: {len(events)}  Hunts run: {len(results)}")
    for r in results:
        print(f" [{r['verdict']:11}] {r['hunt']} ({r['mitre_technique']}) - {r['match_count']} match(es), {r['ioc_hits']} IOC hit(s)")
        print(f"             Hypothesis: {r['hypothesis']}")
    print(f"Findings written to {args.out}")


if __name__ == "__main__":
    main()
