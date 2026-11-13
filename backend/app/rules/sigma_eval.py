"""Minimal Sigma evaluator over ARGUS-normalised events, used ONLY to test generated rules against
labelled datasets. It supports the subset of Sigma that ARGUS generates (field/value maps, lists,
keywords, contains/startswith/endswith/all/re modifiers, and/or/not, '1 of' / 'all of')."""
import re

# Sigma field name -> accessor on a normalised event dict
FIELD_MAP = {
    "EventID": lambda e: e["data"].get("event_id"), "IpAddress": lambda e: e.get("src_ip"), "SourceIp": lambda e: e.get("src_ip"),
    "TargetUserName": lambda e: e.get("user"), "User": lambda e: e.get("user"), "CommandLine": lambda e: e["data"].get("command_line"),
    "ScriptBlockText": lambda e: e["data"].get("command_line"), "Image": lambda e: e["data"].get("image"), "ParentImage": lambda e: e["data"].get("parent_image"),
    "DestinationIp": lambda e: e.get("dst_ip"), "DestinationPort": lambda e: e.get("dst_port"), "QueryName": lambda e: e.get("domain"),
    "Computer": lambda e: e.get("host"), "c-uri": lambda e: e.get("url"), "cs-host": lambda e: e.get("domain"),
    "dst_ip": lambda e: e.get("dst_ip"), "dst_port": lambda e: e.get("dst_port"), "src_ip": lambda e: e.get("src_ip"), "query": lambda e: e.get("domain"),
}
LOGSOURCE_FIELDS = {
    ("windows", "security", None): {"EventID", "IpAddress", "TargetUserName", "Computer"},
    ("windows", None, "process_creation"): {"CommandLine", "Image", "ParentImage", "User", "Computer"},
    ("windows", None, "ps_script"): {"ScriptBlockText", "Computer"},
    ("windows", None, "network_connection"): {"DestinationIp", "DestinationPort", "SourceIp", "Image", "Computer"},
    (None, None, "dns_query"): {"QueryName", "Computer"},
    (None, None, "dns"): {"query"},
    (None, None, "firewall"): {"dst_ip", "dst_port", "src_ip"},
    (None, None, "proxy"): {"c-uri", "cs-host"},
    ("linux", "sshd", None): set(), ("linux", "auth", None): set(),  # keyword-only
}
CATEGORY_FILTER = {
    ("windows", "security", None): lambda e: e["category"] == "authentication",
    ("windows", None, "process_creation"): lambda e: e["category"] == "process",
    ("windows", None, "ps_script"): lambda e: e["category"] == "process",
    ("windows", None, "network_connection"): lambda e: e["category"] == "network",
    (None, None, "dns_query"): lambda e: e["category"] == "dns", (None, None, "dns"): lambda e: e["category"] == "dns",
    (None, None, "firewall"): lambda e: e["category"] == "network", (None, None, "proxy"): lambda e: e["category"] in ("web", "network"),
    ("linux", "sshd", None): lambda e: e["category"] == "authentication", ("linux", "auth", None): lambda e: e["category"] == "authentication",
}


def logsource_key(ls: dict):
    return (ls.get("product"), ls.get("service"), ls.get("category"))


def _match_value(actual, expected, mods: list[str]) -> bool:
    if actual is None:
        return False
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    a, x = str(actual).lower(), str(expected).lower()
    if "contains" in mods:
        return x in a
    if "startswith" in mods:
        return a.startswith(x)
    if "endswith" in mods:
        return a.endswith(x)
    return a == x


def _match_selection(sel, event: dict) -> bool:
    text = (str(event["data"].get("raw") or "") + " " + event.get("summary", "") + " " + str(event["data"].get("command_line") or "")).lower()
    if isinstance(sel, list):  # keyword list (OR) or list of maps (OR)
        return any(_match_selection(s, event) if isinstance(s, dict) else str(s).lower() in text for s in sel)
    if not isinstance(sel, dict):
        return str(sel).lower() in text
    for key, expected in sel.items():
        name, *mods = key.split("|")
        values = expected if isinstance(expected, list) else [expected]
        if name == "":  # '|all': [keywords]
            ok = all(str(v).lower() in text for v in values) if "all" in mods else any(str(v).lower() in text for v in values)
        else:
            acc = FIELD_MAP.get(name)
            actual = acc(event) if acc else None
            ok = all(_match_value(actual, v, mods) for v in values) if "all" in mods else any(_match_value(actual, v, mods) for v in values)
        if not ok:
            return False
    return True


def _eval_condition(cond: str, results: dict[str, bool]) -> bool:
    tokens = re.findall(r"\(|\)|\b1 of [\w*]+|\ball of [\w*]+|\band\b|\bor\b|\bnot\b|[\w*]+", cond)
    pos = 0

    def atom():
        nonlocal pos
        t = tokens[pos]
        pos += 1
        if t == "(":
            v = expr()
            pos += 1
            return v
        if t == "not":
            return not atom()
        if t.startswith(("1 of ", "all of ")):
            pat = t.split(" of ", 1)[1]
            names = [n for n in results if re.fullmatch(pat.replace("*", ".*"), n)] if pat != "them" else list(results)
            vals = [results[n] for n in names]
            return (any(vals) if t.startswith("1 of") else all(vals)) if vals else False
        return results.get(t, False)

    def and_expr():
        nonlocal pos
        v = atom()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            v = atom() and v
        return v

    def expr():
        nonlocal pos
        v = and_expr()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            v = and_expr() or v
        return v

    return expr()


def rule_matches(rule: dict, event: dict) -> bool:
    filt = CATEGORY_FILTER.get(logsource_key(rule.get("logsource", {})))
    if filt and not filt(event):
        return False
    det = rule["detection"]
    results = {name: _match_selection(sel, event) for name, sel in det.items() if name != "condition"}
    return _eval_condition(str(det["condition"]), results)


def used_fields(rule: dict) -> set[str]:
    fields = set()

    def walk(sel):
        if isinstance(sel, dict):
            for k in sel:
                name = k.split("|")[0]
                if name:
                    fields.add(name)
        elif isinstance(sel, list):
            for s in sel:
                walk(s)

    for name, sel in rule.get("detection", {}).items():
        if name != "condition":
            walk(sel)
    return fields
