# Architecture - Threat Hunting Platform

## Data flow

```
demo_data/endpoint_events.json  --\
demo_data/iocs.json             --->  src/threat_hunt.py
src/hunts.json                  --/       |
                                          v
                                  hunt runner: for each hunt,
                                  match events by field + IOC
                                          |
                                  verdict per hunt:
                                  Confirmed / Partial / No evidence
                                          |
                                  out/findings.json + terminal report
```

## Hunt method

Every hunt follows the same structure, taken from real threat hunting practice:

1. **Hypothesis** - a falsifiable statement, e.g. "an attacker is using encoded
   PowerShell on at least one host".
2. **Query** - a field match on the normalised event schema, plus an optional
   IOC list to match against.
3. **Evidence** - the matching events, listed in full so a reviewer can check them.
4. **Verdict** - Confirmed (2+ matching events), Partial (1 match), or No evidence
   (0 matches). A No evidence verdict is a valid result: it refutes the hypothesis
   for this dataset, and the demo includes one on purpose.

## Hunt definitions

Hunts live in `src/hunts.json`. Each entry has `id`, `name`, `hypothesis`,
`mitre_tactic`, `mitre_technique`, `field`, `value`, and optional `ioc_type`.
The runner is generic: it does not know what any individual hunt means.

## How to write a new hunt

1. Write the hypothesis in one sentence.
2. Add an entry to `src/hunts.json` with the field and value to match.
3. Add a matching event to `demo_data/endpoint_events.json` (or deliberately
   add none, to demonstrate a No evidence verdict).
4. Add any IOCs to `demo_data/iocs.json`.
5. Run the tool and check the verdict in `out/findings.json`.

## Limitations (honest)

- The event schema is a demo subset of real endpoint telemetry (Sysmon / EDR).
- Queries are exact substring matches, not a query language.
- No live collection: hunts run over a static file, which is the right scope for a portfolio demo.
