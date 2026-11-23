# 04 - Threat Hunting Platform

A minimal threat hunting platform in pure Python (standard library only). It runs named hunts, written as hypotheses, over synthetic endpoint telemetry, matches indicators of compromise (IOCs), and writes findings with the evidence that supports or refutes each hypothesis.

No live endpoints, no agents, no network calls. All telemetry in `demo_data/` is synthetic.

## What it does

- Loads endpoint events (process, network, file, registry) from `demo_data/endpoint_events.json`
- Loads IOCs (domains, IPs, hashes, process names) from `demo_data/iocs.json`
- Runs 5 hunts from `src/hunts.json`, each with a hypothesis, a query, and a MITRE ATT&CK mapping
- Reports each hunt as Confirmed, Partial, or No evidence, with the matching events
- Writes `out/findings.json`

## Hunts and MITRE ATT&CK mapping

| Hunt | Tactic | Technique |
|---|---|---|
| hunt-encoded-powershell | Execution | T1059.001 PowerShell |
| hunt-living-off-the-land | Defense Evasion | T1218 Signed Binary Proxy Execution |
| hunt-c2-beaconing | Command and Control | T1071.001 Web Protocols |
| hunt-persistence-registry | Persistence | T1547.001 Registry Run Keys |
| hunt-credential-dumping | Credential Access | T1003.001 LSASS Memory |

## How to run

```bash
cd 04-threat-hunting-platform
python3 src/threat_hunt.py --events demo_data/endpoint_events.json --iocs demo_data/iocs.json --out out/findings.json
```

Expected output: 5 hunts run: 2 Confirmed, 2 Partial, 1 No evidence (credential dumping, which is the negative control).

## Files

- `src/threat_hunt.py` - hunt runner, IOC matcher, reporting
- `src/hunts.json` - hunt definitions with hypotheses and ATT&CK mapping
- `demo_data/endpoint_events.json` - 20 synthetic endpoint events
- `demo_data/iocs.json` - 6 demo IOCs (domains, IPs, hashes, processes)
- `docs/architecture.md` - architecture, hunt method, and how to write a new hunt
- `requirements.txt` - standard library only

## What an employer sees

Structured hunting, not random searching: hypothesis, query, evidence, verdict. Each hunt is data, so a new hunt is a JSON entry, not a code change. The next step is adding a hunt for a technique in the ATT&CK matrix you have not covered yet.
