# Contributing

## Ground rules

1. **No finding without evidence.** A detector returns the evidence, events and indicator values that
   support its claim. The Verifier will reject it otherwise.
2. **Say what was observed, not what it means.** Descriptions state the measurement and its benign
   explanations. Only the combination rules in the correlation engine may raise a classification.
3. **Nothing is executed, fetched or rendered** from evidence unless it goes through `security/`.
4. **No fabricated data paths.** No placeholder responses, no random scores, no UI element that is not
   backed by backend state. Sample data lives in `data/samples` and is labelled as sample wherever shown.
5. **A change ships with a test** that fails without it.

## Adding an evidence format

```python
# backend/app/ingestion/pipelines.py
@pipeline("zeek_conn")
def ingest_zeek(data: bytes, ctx: IngestContext) -> ParsedEvidence:
    pe = ParsedEvidence()
    ...  # fill pe.meta, pe.events (EventDraft), pe.indicators (pe.add_ioc), pe.relations, pe.findings
    return pe
```

Then: teach `security/uploads.sniff_kind` to recognise it, add the kind to `KINDS`, add a sample file and a
scenario in `scripts/generate_samples.py`, and a label in `frontend/src/lib/format.ts`.

## Adding a detector

Put the logic in `analysis/`, return plain dicts, and convert to `FindingDraft` in the pipeline. Choose
`classification` conservatively (`insufficient_evidence` for weak single signals). If the claim is
countable or reproducible, add a re-derivation branch in `agents/verifier.py`.

## Adding an ATT&CK mapping or rule template

`mitre/mapping.py`: add the technique to `T` (id, name and tactics exactly as on attack.mitre.org) and a
branch in `_rules` whose rationale cites what the evidence showed. `rules/generator.py`: add a branch in
`_drafts_for`; if it uses new Sigma fields, add them to `FIELD_MAP` and `LOGSOURCE_FIELDS` in
`rules/sigma_eval.py`.

## Frontend

- Colours, type and radii come from `tailwind.config.ts`. Do not introduce literal colours in components
  (3D materials read the same hex values from `lib/format.ts` and `lib/graph.ts`).
- Amber is for signal and the active element, cyan for data and links, red only for threat state.
- Every new view needs loading, empty and error states, and must work at 390 px.
- Anything animated must respect `useReducedMotion()`; any 3D view needs a 2D equivalent.

## Before opening a pull request

```bash
cd backend && ../.venv/bin/python -m pytest
cd frontend && npm run typecheck && npm run build
```
