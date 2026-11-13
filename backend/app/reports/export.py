"""Report export: Markdown and standalone print-ready HTML (autoescaped). JSON is the stored content itself."""
from jinja2 import Environment, select_autoescape

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))

HTML = _env.from_string("""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ARGUS Forensic Dossier {{ r.metadata.investigation_id }}</title>
<style>
@page { size: A4; margin: 18mm 16mm; }
*{box-sizing:border-box} body{font:10.5pt/1.5 'Inter',system-ui,sans-serif;color:#151A22;margin:0;background:#fff}
main{max-width:820px;margin:0 auto;padding:32px}
h1{font:600 26pt/1.1 'Space Grotesk',system-ui,sans-serif;margin:0 0 4px;letter-spacing:-.02em}
h2{font:600 9pt/1 'Space Grotesk',system-ui,sans-serif;letter-spacing:.16em;text-transform:uppercase;color:#5b6675;border-top:1px solid #151A22;padding-top:10px;margin:34px 0 12px;break-after:avoid}
.mono,code{font-family:'IBM Plex Mono',ui-monospace,monospace;font-size:8.5pt;word-break:break-all}
.cover{border-bottom:3px solid #151A22;padding-bottom:18px;margin-bottom:8px}
.eyebrow{font:500 8pt 'IBM Plex Mono',monospace;letter-spacing:.2em;color:#b06a12;text-transform:uppercase}
.verdict{display:inline-block;margin-top:14px;padding:8px 14px;border:1.5px solid #151A22;font:600 11pt 'Space Grotesk',sans-serif}
.v-malicious{border-color:#b3202b;color:#b3202b}.v-suspicious{border-color:#b06a12;color:#b06a12}.v-benign{border-color:#157a86;color:#157a86}
table{width:100%;border-collapse:collapse;margin:6px 0 4px;font-size:9pt} th{text-align:left;font:600 7.5pt 'IBM Plex Mono',monospace;letter-spacing:.1em;text-transform:uppercase;color:#5b6675;border-bottom:1px solid #151A22;padding:5px 6px}
td{padding:6px;border-bottom:1px solid #d9dee5;vertical-align:top}
.f{border-left:3px solid #9aa4b1;padding:2px 0 2px 12px;margin:0 0 14px;break-inside:avoid}.f.critical,.f.high{border-color:#b3202b}.f.medium{border-color:#b06a12}.f.low{border-color:#157a86}
.f h3{font:600 10.5pt 'Inter',sans-serif;margin:0 0 2px}.tag{font:500 7.5pt 'IBM Plex Mono',monospace;letter-spacing:.08em;text-transform:uppercase;color:#5b6675;margin-right:10px}
ul{padding-left:18px;margin:6px 0} li{margin-bottom:5px} .muted{color:#5b6675} .ref{font:8pt 'IBM Plex Mono',monospace;color:#5b6675}
footer{margin-top:40px;border-top:1px solid #151A22;padding-top:8px;font:7.5pt 'IBM Plex Mono',monospace;color:#5b6675}
</style></head><body><main>
<div class="cover"><div class="eyebrow">ARGUS · Forensic Dossier</div><h1>{{ r.metadata.title }}</h1>
<div class="mono muted">{{ r.metadata.investigation_id }} · generated {{ r.metadata.report_generated }} UTC · {{ r.metadata.engine }}</div>
<div class="verdict v-{{ r.verdict.value }}">{{ r.verdict.label }}{% if r.verdict.confidence %} · confidence {{ '%d' % (r.verdict.confidence * 100) }}%{% endif %}</div>
<div class="ref" style="margin-top:6px">{{ r.verdict.rule }}</div></div>
<h2>Executive summary</h2>{% for s in r.executive_summary %}<p>{{ s.text }}{% if s.finding_ids %} <span class="ref">[{{ s.finding_ids | join(', ') }}]</span>{% endif %}</p>{% endfor %}
<h2>Investigation metadata</h2><table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Created</td><td class="mono">{{ r.metadata.created_at }}</td></tr><tr><td>Analysis started</td><td class="mono">{{ r.metadata.analysis_started }}</td></tr>
<tr><td>Narrative source</td><td>{{ r.metadata.narrative_source }}</td></tr>
<tr><td>Configuration</td><td class="mono">network_fetch={{ r.metadata.configuration.network_fetch }} · intel_offline={{ r.metadata.configuration.intel_offline }} · llm={{ r.metadata.configuration.llm_provider }}</td></tr></table>
<h2>Evidence</h2><table><tr><th>ID</th><th>Kind</th><th>Name</th><th>SHA-256</th><th>Ingested (UTC)</th></tr>
{% for e in r.evidence %}<tr><td class="mono">{{ e.id }}</td><td>{{ e.kind }}</td><td>{{ e.name }}</td><td class="mono">{{ e.sha256 }}</td><td class="mono">{{ e.ingested_at[:19] }}</td></tr>{% endfor %}</table>
<h2>Findings</h2>{% if not r.findings %}<p class="muted">No findings above informational level.</p>{% endif %}
{% for f in r.findings %}<div class="f {{ f.severity }}"><h3>{{ f.title }}</h3>
<div><span class="tag">{{ f.severity }}</span><span class="tag">{{ f.classification | replace('_',' ') }}</span><span class="tag">basis: {{ f.basis | replace('_',' ') }}</span><span class="tag">confidence {{ '%d' % (f.confidence * 100) }}%</span></div>
<p>{{ f.description }}</p><div class="ref">{{ f.id }} · evidence {{ f.evidence_ids | join(', ') }} · verifier: {{ f.verification_status }} — {{ f.verification_notes }}</div></div>{% endfor %}
{% if r.timeline.attack_sequence %}<h2>Inferred attack sequence</h2><p class="muted">{{ r.timeline.attack_sequence.basis }}</p>
<table><tr><th>Time (UTC)</th><th>Phase</th><th>Finding</th></tr>{% for s in r.timeline.attack_sequence.steps %}<tr><td class="mono">{{ (s.at or 'untimed')[:19] }}</td><td>{{ s.phase | replace('_',' ') }}</td><td>{{ s.title }} <span class="ref">[{{ s.finding_id }}]</span></td></tr>{% endfor %}</table>{% endif %}
<h2>Timeline of notable events</h2>{% if not r.timeline.notable_events %}<p class="muted">No dated events are tied to findings.</p>{% else %}
<table><tr><th>Time (UTC)</th><th>Layer</th><th>Event</th><th>Time basis</th></tr>{% for t in r.timeline.notable_events %}<tr><td class="mono">{{ t.at[:19] }}</td><td>{{ t.layer }}</td><td>{{ t.summary }} <span class="ref">[{{ t.evidence_id }} · {{ t.record_ref }}]</span></td><td>{{ t.time_basis }}</td></tr>{% endfor %}</table>{% endif %}
<h2>MITRE ATT&amp;CK mapping</h2>{% if not r.mitre %}<p class="muted">No technique met the evidence bar for mapping.</p>{% else %}
<table><tr><th>Technique</th><th>Tactics</th><th>Why it applies</th></tr>{% for m in r.mitre %}<tr><td><span class="mono">{{ m.technique_id }}</span><br>{{ m.technique_name }}</td><td>{{ m.tactics | join(', ') }}</td><td>{{ m.rationale }} <span class="ref">[{{ m.finding_id }}]</span></td></tr>{% endfor %}</table>{% endif %}
<h2>Indicators ({{ r.indicator_total }})</h2><table><tr><th>Type</th><th>Value</th><th>Evidence</th></tr>
{% for i in r.indicators[:80] %}<tr><td>{{ i.type }}</td><td class="mono">{{ i.value }}</td><td class="mono">{{ i.evidence_ids | join(', ') }}</td></tr>{% endfor %}</table>
{% if r.threat_intelligence %}<h2>Threat intelligence (reputation, not evidence)</h2><table><tr><th>Indicator</th><th>Source</th><th>Verdict</th><th>Summary</th></tr>
{% for t in r.threat_intelligence %}<tr><td class="mono">{{ t.indicator }}</td><td>{{ t.source }} ({{ t.reliability }})</td><td>{{ t.verdict }}</td><td>{{ t.summary }}</td></tr>{% endfor %}</table>{% endif %}
<h2>Confidence and limitations</h2><ul>{% for l in r.confidence_and_limitations %}<li>{{ l }}</li>{% endfor %}</ul>
<h2>Recommended actions</h2>{% if not r.recommended_actions %}<p class="muted">No action recommended on the current evidence.</p>{% endif %}
<ul>{% for a in r.recommended_actions %}<li><strong>[{{ a.priority }}]</strong> {{ a.action }} <span class="ref">{% if a.based_on %}[{{ a.based_on | join(', ') }}]{% endif %} · requires human approval</span></li>{% endfor %}</ul>
<footer>Generated by ARGUS. Findings are evidence-backed and independently verified; narrative and sequences marked "inferred" are hypotheses. This report does not constitute attribution.</footer>
</main></body></html>""")


def to_html(content: dict) -> str:
    return HTML.render(r=content)


def to_markdown(c: dict) -> str:
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
    L = [f"# ARGUS Forensic Dossier: {c['metadata']['title']}", "", f"`{c['metadata']['investigation_id']}` · generated {c['metadata']['report_generated']} UTC", "",
         f"**Verdict:** {c['verdict']['label']}" + (f" (confidence {c['verdict']['confidence']:.0%})" if c['verdict'].get('confidence') else ""), "", "## Executive summary", ""]
    L += [s["text"] + (f" `[{', '.join(s['finding_ids'])}]`" if s["finding_ids"] else "") + "\n" for s in c["executive_summary"]]
    L += ["## Evidence", "", "| ID | Kind | Name | SHA-256 |", "|---|---|---|---|"] + [f"| {e['id']} | {e['kind']} | {esc(e['name'])} | `{e['sha256']}` |" for e in c["evidence"]]
    L += ["", "## Findings", ""]
    for f in c["findings"]:
        L += [f"### {f['title']}", "", f"`{f['severity']}` · `{f['classification']}` · basis `{f['basis']}` · confidence {f['confidence']:.0%}", "", f["description"], "",
              f"Evidence: {', '.join(f['evidence_ids'])}. Verifier: {f['verification_status']} ({f['verification_notes']})", ""]
    if c["timeline"].get("attack_sequence"):
        L += ["## Inferred attack sequence", "", c["timeline"]["attack_sequence"]["basis"], ""] + [f"- {(s['at'] or 'untimed')[:19]} · {s['phase']} · {s['title']} `[{s['finding_id']}]`" for s in c["timeline"]["attack_sequence"]["steps"]] + [""]
    L += ["## MITRE ATT&CK", ""] + ([f"- **{m['technique_id']} {m['technique_name']}** ({', '.join(m['tactics'])}): {m['rationale']} `[{m['finding_id']}]`" for m in c["mitre"]] or ["No technique met the evidence bar."])
    L += ["", "## Confidence and limitations", ""] + [f"- {x}" for x in c["confidence_and_limitations"]]
    L += ["", "## Recommended actions (all require human approval)", ""] + ([f"- [{a['priority']}] {a['action']}" for a in c["recommended_actions"]] or ["None on current evidence."])
    return "\n".join(L) + "\n"
