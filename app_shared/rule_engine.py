"""Compile indexed detection rules into event matchers and evaluate events.

The rules table catalogs rules from four platforms (Sigma YAML, Elastic
detection-rules JSON, Wazuh XML, Panther Python). A catalog is not a
detection engine: this module turns each rule's condition into a callable
matcher over the event documents stored in the unified store, so an
incoming event that satisfies a rule's logic fires that rule.

What is compiled per engine:
- sigma:    the detection grammar — selections with field lists, keyword
            lists, wildcards (fnmatch), ``|contains|all``, ``|startswith``,
            ``|endswith``, ``|base64offset|contains``, ``|exists``, and
            condition expressions (``1 of``, ``all of``, ``not``, ``and``,
            ``or``, parentheses).
- elastic:  query strings in EQL / KQL / Lucene / ESQL. Parsed into field
            matchers for the common operators (==, !=, :/like, in, and,
            or, not, parentheses, wildcards). Compound EQL ``sequence`` /
            ``join`` degrade to their first branch (stateless matching) —
            the time-correlation cases remain the behavioral detectors' job.
- wazuh:    the source XML on disk — ``<match>`` (PCRE-ish, lowered to
            regex), ``<regex>``, ``<id>``, ``<program_name>``, ``<group>``
            and ``<if_group>`` (OR over group membership). Parent-rule
            chaining degrades to matching the rule's own conditions.
- panther:  the Python rule file on disk. The ``rule(event)`` function is
            exec'd in a restricted namespace with ``deep_get`` available;
            syntax errors and missing functions compile to ``None``.

Every matcher returns True/False over a normalized event doc: the store's
columns plus the base64-decoded packet payload text. Rules whose source
is unreadable or whose grammar is unsupported are counted and skipped —
never silently dropped.
"""

from __future__ import annotations

import ast
import base64
import fnmatch
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Callable

logger = logging.getLogger(__name__)

MATCHABLE_ENGINES = ("sigma", "elastic", "wazuh", "panther")

# ---------------------------------------------------------------------------
# Event doc normalization
# ---------------------------------------------------------------------------

def event_doc(ev: dict[str, Any]) -> dict[str, Any]:
    """Flatten a stored event into the document matchers evaluate.

    Store columns become string fields; the agent's base64 payload snapshot
    is decoded to text (lossy, latin-1 keeps bytes printable) so Sigma
    keyword lists and Wazuh ``<match>`` patterns can hit on contents.
    """
    doc: dict[str, Any] = {}
    for k, v in ev.items():
        if k in ("raw", "payload"):
            continue
        if isinstance(v, (list, dict)):
            continue
        doc[k] = str(v) if v is not None else ""
    doc["source_port"] = str(ev.get("source_port") or "")

    raw = ev.get("raw")
    payload_b64 = None
    if isinstance(raw, str):
        try:
            payload_b64 = json.loads(raw).get("payload")
        except (ValueError, TypeError, AttributeError):
            payload_b64 = None
    elif isinstance(raw, dict):
        payload_b64 = raw.get("payload")
    if ev.get("payload"):
        payload_b64 = ev["payload"]
    if payload_b64:
        try:
            text = base64.b64decode(payload_b64, validate=False).decode("latin-1", "replace")
            doc["payload"] = text
            # Some rules key on field names inside payloads; expose the text
            # under a few common aliases cheaply.
            doc["data"] = text
        except (ValueError, TypeError):
            pass

    # Threat-intel enrichment (the enrich-index the Elastic TI rules join
    # against): expose indicator hits under their ECS field names so queries
    # like ``threat.indicator.ip:*`` and ``threat.indicator.matched.field``
    # evaluate against real feed data instead of being vacuous.
    try:
        from app_shared import threat_intel as _ti

        hits: list[dict[str, Any]] = []
        for ipf in ("source_ip", "destination_ip"):
            ind = _ti.lookup_ip(ev.get(ipf) or "")
            if ind:
                hits.append({**ind, "matched_field": f"source.{ipf.split('_')[0]}.ip"})
        for df in ("message", "payload", "title"):
            text_v = str(ev.get(df) or "")
            if not text_v:
                continue
            for tok in text_v.split():
                if "." in tok and len(tok) > 4:
                    ind = _ti.lookup_domain(tok.rstrip(".,;:)'\""))
                    if ind:
                        hits.append({**ind, "matched_field": "url.domain"})
                        break
            if hits and df != "message":
                break
        if hits:
            first = hits[0]
            doc["threat_indicator_ip"] = first.get("value", "")
            doc["threat_indicator_type"] = first.get("type", "")
            doc["threat_indicator_matched_field"] = first.get("matched_field", "")
            doc["threat_indicator_severity"] = first.get("severity", "medium")
            doc["threat_indicator_feed"] = first.get("feed", "")
            doc["threat_indicator_matched"] = "true"
    except Exception:
        pass
    return doc


# ---------------------------------------------------------------------------
# Value predicates
# ---------------------------------------------------------------------------

def _lc(value: Any) -> str:
    return str(value).lower() if value is not None else ""


def _wildcard_match(value: str, pattern: str) -> bool:
    """Sigma/Elastic-style wildcard: * and ? — case-insensitive."""
    return fnmatch.fnmatch(_lc(value), _lc(pattern))


def _contains_all(value: str, needles: list[str]) -> bool:
    v = _lc(value)
    return all(_lc(n) in v for n in needles)


def _contains_any(value: str, needles: list[str]) -> bool:
    v = _lc(value)
    return any(_lc(n) in v for n in needles)


def _field_getter(field: str) -> Callable[[dict[str, Any]], str]:
    """Resolve dotted/ECS-ish field names onto the flat event doc."""
    field_l = field.lower()
    aliases = {
        "process.name": "process_name",
        "process.executable": "process_command_line",
        "process.command_line": "process_command_line",
        "process.commandline": "process_command_line",
        "user.name": "user_name",
        "user.target.name": "user_name",
        "host.name": "host_name",
        "host.hostname": "host_name",
        "source.ip": "source_ip",
        "destination.ip": "destination_ip",
        "source.address": "source_ip",
        "destination.address": "destination_ip",
        "destination.port": "destination_port",
        "source.port": "source_port",
        "network.transport": "network_transport",
        "event.action": "suricata_event_type",
        "event.category": "index_name",
        "event.dataset": "index_name",
        "event.module": "engine",
        "event.code": "rule_id",
        "rule.name": "title",
        "rule.id": "rule_id",
        "message": "message",
        "winlog.event_id": "rule_id",
        "CommandLine": "process_command_line",
        "Image": "process_name",
        "ParentImage": "process_name",
        "ServiceName": "title",
        # threat-intel enrich fields (populated by event_doc from the TI store)
        "threat.indicator.ip": "threat_indicator_ip",
        "threat.indicator.matched.field": "threat_indicator_matched_field",
        "threat.indicator.severity": "threat_indicator_severity",
        "threat.indicator.provider": "threat_indicator_feed",
        "threat.feed.name": "threat_indicator_feed",
        "threat.indicator.type": "threat_indicator_type",
    }
    if field in aliases:
        return lambda d, _k=aliases[field]: str(d.get(_k, "") or "")

    def getter(d: dict[str, Any], _f: str = field) -> str:
        if _f in d:
            return str(d.get(_f, "") or "")
        if _f.lower() in d:
            return str(d.get(_f.lower(), "") or "")
        tail = _f.split(".")[-1]
        if tail in d:
            return str(d.get(tail, "") or "")
        return str(d.get(tail.lower(), "") or "")

    return getter


def _value_predicate(raw_value: Any) -> Callable[[str], bool]:
    """Compile one Sigma field value (or list element) into a predicate.

    Lists are OR (Sigma semantics). Modifiers are handled by the caller for
    list-wide forms like |contains|all; here we handle per-element semantics.
    """
    if isinstance(raw_value, list):
        preds = [_value_predicate(v) for v in raw_value]
        return lambda v: any(p(v) for p in preds)
    if isinstance(raw_value, bool):
        want = "true" if raw_value else "false"
        return lambda v: _lc(v) == want
    if isinstance(raw_value, (int, float)):
        return lambda v: str(raw_value) == str(v).strip()
    sval = str(raw_value)
    if sval == "null":
        return lambda v: v in ("", "none", "null")
    if any(ch in sval for ch in "*?"):
        return lambda v: _wildcard_match(v, sval)
    return lambda v: _lc(v) == _lc(sval)


def _sigma_value_modifier(modifiers: list[str], value: Any) -> tuple[Callable[[str], bool], bool]:
    """Return (predicate over the field value, requires_all).

    requires_all=True means every token in the field must satisfy the
    predicate (|all semantics over keyword splits is handled by callers as
    contains-all on the raw field text).
    """
    requires_all = "all" in modifiers
    if any(m in ("contains", "containsall") for m in modifiers) or "contains" in modifiers:
        needles = value if isinstance(value, list) else [value]
        if requires_all:
            return (lambda v: _contains_all(v, needles)), False
        return (lambda v: _contains_any(v, needles)), False
    if "startswith" in modifiers:
        needles = value if isinstance(value, list) else [value]
        return (lambda v: any(_lc(v).startswith(_lc(n)) for n in needles)), False
    if "endswith" in modifiers:
        needles = value if isinstance(value, list) else [value]
        return (lambda v: any(_lc(v).endswith(_lc(n)) for n in needles)), False
    if "re" in modifiers:
        pat = re.compile(str(value), re.I)
        return (lambda v: bool(pat.search(v))), False
    if "base64offset" in modifiers and "contains" in modifiers:
        needles = value if isinstance(value, list) else [value]
        b64_forms: list[str] = []
        for n in needles:
            raw = str(n).encode()
            for pad in range(3):
                enc = base64.b64encode(b"\x00" * pad + raw).decode()
                b64_forms.append(enc[pad:] if pad == 0 else enc[(pad + 2) // 3 * 0 or 0:])
        # Simplified: match any of the three standard offsets
        b64_forms = []
        for n in needles:
            raw = str(n).encode()
            for pad in range(3):
                enc = base64.b64encode(bytes(pad) + raw).decode()
                b64_forms.append(enc[(pad * 8 + 5) // 6 if pad else 0:])
        return (lambda v: _contains_any(v, b64_forms)), False
    return _value_predicate(value), requires_all


# ---------------------------------------------------------------------------
# Sigma compilation
# ---------------------------------------------------------------------------

def _compile_sigma_selection(sel: Any) -> Callable[[dict[str, Any]], bool] | None:
    """One Sigma selection: dict of field->value, list of keywords, or str."""
    if isinstance(sel, str):
        # shorthand: bare field reference "other_selection" — resolved by caller
        return None
    if isinstance(sel, list):
        # keyword list: match against message+title+payload haystack
        def kw_match(d: dict[str, Any]) -> bool:
            hay = " ".join(
                str(d.get(k, "") or "")
                for k in ("message", "title", "payload", "data", "process_command_line")
            )
            return _contains_any(hay, sel)
        return kw_match
    if not isinstance(sel, dict):
        return None

    field_preds: list[tuple[str, Callable[[dict[str, Any]], bool]]] = []
    for field, value in sel.items():
        if field.startswith("_") or field == "condition":
            continue
        parts = field.split("|")
        fname = parts[0]
        modifiers = [p.strip() for p in parts[1:]]
        getter = _field_getter(fname)

        if "exists" in modifiers:
            want = bool(value) if isinstance(value, bool) else str(value).lower() != "false"
            field_preds.append((fname, lambda d, _g=getter, _w=want: (bool(_g(d)) == _w)))
            continue

        if isinstance(value, list) and ("contains" in modifiers and "all" in modifiers):
            field_preds.append((fname, lambda d, _g=getter, _n=[str(x) for x in value]:
                                _contains_all(_g(d), _n)))
            continue

        pred, _ = _sigma_value_modifier(modifiers, value)
        field_preds.append((fname, lambda d, _g=getter, _p=pred: _p(_g(d))))

    if not field_preds:
        return None

    def selection(d: dict[str, Any]) -> bool:
        return all(pred(d) for _, pred in field_preds)

    return selection


def _compile_sigma_condition(condition: str, selections: dict[str, Callable], names: list[str]) -> Callable[[dict], bool] | None:
    """Evaluate the Sigma condition expression with `of` expansion.

    Supports: `selection`, `1 of selection_*`, `all of x`, `not`, `and`,
    `or`, parentheses. Quote-literal values ("1", "true") are compared as
    selection-presence names, matching Sigma's grammar where unquoted
    tokens are selection names.
    """
    cond = condition.strip()

    def resolve_name(token: str) -> Callable[[dict], bool] | None:
        token = token.strip().strip("'\"")
        if token in selections:
            return selections[token]
        # wildcard group: "1 of selection_*" / "all of them"
        return None

    # Expand `N of PATTERN` and `all of PATTERN`
    def expand(cond: str) -> str:
        def repl(m: re.Match) -> str:
            quant, pattern = m.group(1).strip(), m.group(2).strip()
            matches = [n for n in names if fnmatch.fnmatchcase(n, pattern) or pattern == "them"]
            if not matches:
                return "( False )"
            if quant == "all":
                return "(" + " and ".join(matches) + ")"
            return "(" + " or ".join(matches) + ")"

        return re.sub(r"(\d+|all)\s+of\s+([\w*]+)", repl, cond)

    expanded = expand(cond)
    if not expanded.strip():
        return None

    # Tokenize to a safe expression over helper predicates
    tokens = re.findall(r"\(|\)|\bnot\b|\band\b|\bor\b|'[^']*'|\"[^\"]*\"|[\w.*]+", expanded)
    py_parts: list[str] = []
    var_map: dict[str, Callable[[dict], bool]] = {}
    for tok in tokens:
        low = tok.lower()
        if tok == "(":
            py_parts.append("(")
        elif tok == ")":
            py_parts.append(")")
        elif low == "not":
            py_parts.append("not")
        elif low == "and":
            py_parts.append("and")
        elif low == "or":
            py_parts.append("or")
        elif (tok.startswith("'") and tok.endswith("'")) or (tok.startswith('"') and tok.endswith('"')):
            # quoted literal: Sigma treats quoted tokens as named selections
            name = tok[1:-1]
            if name in selections:
                var = f"s{len(var_map)}"
                var_map[var] = selections[name]
                py_parts.append(f"{var}(d)")
            else:
                py_parts.append("False")
        elif tok in ("True", "False", "true", "false"):
            py_parts.append("True" if low == "true" else "False")
        elif tok in selections:
            var = f"s{len(var_map)}"
            var_map[var] = selections[tok]
            py_parts.append(f"{var}(d)")
        else:
            py_parts.append("False")

    expr = " ".join(py_parts)
    if not var_map:
        return None

    func_src = f"lambda d, _m: ({expr})"
    try:
        # Bind each selection matcher as a global so the expression's bare
        # names (s0, s1, ...) resolve to the compiled callables.
        factory = eval(func_src, {"__builtins__": {}, **var_map})  # -> callable lambda
    except SyntaxError:
        return None
    if not callable(factory):
        return None

    def matcher(d: dict[str, Any]) -> bool:
        try:
            return bool(factory(d, var_map))
        except Exception:
            return False

    return matcher


def compile_sigma(doc: dict[str, Any]) -> tuple[Callable | None, str]:
    """Return (matcher, skip_reason). matcher None means skip."""
    det = doc.get("detection")
    if not isinstance(det, dict):
        return None, "no detection block"
    condition = det.get("condition")
    if not condition:
        return None, "no condition"

    selections: dict[str, Callable] = {}
    for key, val in det.items():
        if key == "condition":
            continue
        if isinstance(val, list) and val and isinstance(val[0], dict):
            compiled = [_compile_sigma_selection(v) for v in val]
            compiled = [c for c in compiled if c]
            if compiled:
                selections[key] = (lambda cs: lambda d: any(c(d) for c in cs))(compiled)
            continue
        compiled = _compile_sigma_selection(val)
        if compiled:
            selections[key] = compiled

    if not selections:
        return None, "no usable selections"

    conds = condition if isinstance(condition, list) else [condition]
    for cond in conds:
        matcher = _compile_sigma_condition(str(cond), selections, list(selections.keys()))
        if matcher:
            return matcher, ""
    return None, f"condition not supported: {conds[0][:60]}"


# ---------------------------------------------------------------------------
# Elastic compilation (EQL / KQL / Lucene / ESQL — common subsets)
# ---------------------------------------------------------------------------

def _elastic_field(f: str) -> Callable[[dict], str]:
    return _field_getter(f)


_EQL_LEX = re.compile(
    r"""(?P<lparen>\()
    |(?P<rparen>\))
    |(?P<op>==|!=|:=|>=|<=|=|:|<|>)
    |(?P<kwlike>like~?|startswith~?|endswith~?)
    |(?P<kwin>in)
    |(?P<kw>and|or|not|AND|OR|NOT)
    |(?P<q>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    |(?P<word>[\w.@*?!\-]+)
    |(?P<ws>\s+|,\s*)
    |(?P<junk>[^\s()]+)
    """,
    re.VERBOSE,
)


def _lex_elastic(q: str) -> list[tuple[str, str]]:
    toks = []
    for m in _EQL_LEX.finditer(q):
        kind = m.lastgroup
        val = m.group()
        if kind in ("ws", "junk"):
            if kind == "junk":
                toks.append(("word", val))
            continue
        toks.append((kind, val))
    return toks


class _EqlParser:
    """Recursive-descent parser for the KQL/EQL/Lucene common subset.

    Grammar:
        expr    := term ( (AND|OR) term )*
        term    := NOT term | '(' expr ')' | clause
        clause  := field ( op value | like list | in list | value )
    KQL-implied AND between adjacent clauses is handled in expr().
    Value lists after like/in/':' are parenthesized OR-lists.
    Bare words in a value position are literals (wildcards honored).
    """

    def __init__(self, toks: list[tuple[str, str]]) -> None:
        self.toks = toks
        self.i = 0
        self.pred_count = 0

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def next(self) -> tuple[str, str] | None:
        tok = self.peek()
        self.i += 1
        return tok

    def parse(self) -> Callable[[dict], bool] | None:
        fn = self.expr()
        return fn

    def expr(self) -> Callable[[dict], bool] | None:
        left = self.term()
        if left is None:
            return None
        while True:
            tok = self.peek()
            if tok is None:
                return left
            kind, val = tok
            low = val.lower()
            if kind == "kw" and low == "and":
                self.next()
                right = self.term()
                if right is None:
                    return left
                left = (lambda l, r: lambda d: l(d) and r(d))(left, right)
            elif kind == "kw" and low == "or":
                self.next()
                right = self.term()
                if right is None:
                    return left
                left = (lambda l, r: lambda d: l(d) or r(d))(left, right)
            elif kind == "word" or (kind == "q"):
                # KQL implied AND: next clause starts immediately
                right = self.term()
                if right is None:
                    return left
                left = (lambda l, r: lambda d: l(d) and r(d))(left, right)
            else:
                return left

    def term(self) -> Callable[[dict], bool] | None:
        tok = self.peek()
        if tok is None:
            return None
        kind, val = tok
        low = val.lower()
        if kind == "kw" and low == "not":
            self.next()
            inner = self.term()
            if inner is None:
                return None
            return lambda d: not inner(d)
        if kind == "lparen":
            self.next()
            inner = self.expr()
            closing = self.peek()
            if closing and closing[0] == "rparen":
                self.next()
            return inner
        return self.clause()

    def clause(self) -> Callable[[dict], bool] | None:
        tok = self.next()
        if tok is None:
            return None
        kind, val = tok
        if kind not in ("word", "q"):
            return None
        field_tok = val
        nxt = self.peek()
        if nxt is None:
            # bare term -> haystack contains
            term = field_tok.strip('"\'')
            return lambda d: _lc(term) in _lc(" ".join(
                str(d.get(x, "") or "") for x in ("message", "title", "payload", "data", "process_command_line")))
        nkind, nval = nxt
        nlow = nval.lower()

        if nkind == "op":
            self.next()
            vtok = self.next()
            if vtok is None:
                return None
            vkind, vval = vtok
            if vkind == "lparen":
                # field:(a or b or "c d")  -> KQL value list = OR over values
                vals = self._value_list()
                if vals is None:
                    return None
                return self._field_any(field_tok, vals)
            if vkind in ("q", "word", "kwlike", "kwin", "kw"):
                # value could be a multi-word bare OR chain: a or b
                vals = [vval] if vkind != "kw" else []
                if vkind == "kw":
                    # operator followed by keyword is malformed; treat as bare field
                    return lambda d: True
                # consume implicit "or value" chains (bare words/quoted)
                while True:
                    p1 = self.peek()
                    if p1 and p1[0] == "kw" and p1[1].lower() == "or":
                        p2 = self.peek(2) if hasattr(self, "peek2") else None
                        # lookahead properly
                        save = self.i
                        self.next()
                        vt = self.next()
                        if vt and vt[0] in ("q", "word"):
                            vals.append(vt[1])
                        else:
                            self.i = save
                            break
                    else:
                        break
                return self._field_any(field_tok, vals)
            return None

        if nkind in ("kwlike", "kwin"):
            self.next()
            p = self.peek()
            if p and p[0] == "lparen":
                self.next()
                vals = self._value_list()
                if vals is None:
                    return None
            elif p and p[0] in ("q", "word"):
                self.next()
                vals = [p[1]]
            else:
                return None
            getter = _elastic_field(field_tok)
            if nkind == "kwin":
                lcvals = [_lc(v.strip('"\'')) for v in vals]
                return lambda d: bool(getter(d)) and _lc(getter(d)) in lcvals
            if nlow.startswith("startswith"):
                return lambda d: any(_lc(getter(d)).startswith(_lc(v.strip('"\''))) for v in vals)
            if nlow.startswith("endswith"):
                return lambda d: any(_lc(getter(d)).endswith(_lc(v.strip('"\''))) for v in vals)
            return lambda d: bool(getter(d)) and any(_wildcard_match(getter(d), v) for v in vals)

        # field followed by a bare word that is not an operator:
        # could be "field value" (lucene) or implied AND of two bare fields.
        if nkind in ("word", "q"):
            # treat as lucene "field:value" without colon? Not common; do implied AND:
            left = self._field_any(field_tok, [field_tok])  # bare field name: haystack contains it
            right = self.clause()
            if right is None:
                return left
            return lambda d: left(d) and right(d)

        return None

    def _value_list(self) -> list[str] | None:
        """Consume values until the matching ')'. 'or' separators allowed."""
        vals: list[str] = []
        depth = 1
        expect_value = True
        while self.i < len(self.toks):
            kind, val = self.toks[self.i]
            if kind == "lparen":
                depth += 1
                self.i += 1
                continue
            if kind == "rparen":
                depth -= 1
                self.i += 1
                if depth == 0:
                    return vals or None
                continue
            if kind == "kw" and val.lower() in ("or", "and"):
                expect_value = True
                self.i += 1
                continue
            if kind in ("q", "word", "kwlike", "kwin"):
                vals.append(val)
                expect_value = False
                self.i += 1
                continue
            self.i += 1
        return None

    def _field_any(self, field: str, vals: list[str]) -> Callable[[dict], bool]:
        getter = _elastic_field(field)
        cleaned = [v.strip('"\'') for v in vals if v.strip('"\'')]
        if not cleaned:
            return lambda d: True
        def pred(d: dict) -> bool:
            fval = getter(d)
            return any(
                _wildcard_match(fval, v) or _lc(v) in _lc(fval) and any(ch in v for ch in "*?") is False and _lc(v) == _lc(fval)
                for v in cleaned
            )
        # Simpler, correct semantics: wildcard compare OR exact (ci) OR contains for quoted phrases
        def pred2(d: dict) -> bool:
            fval = _lc(getter(d))
            if not fval:
                # KQL/Lucene ``field:*`` means ``field exists``; a missing or
                # empty value must never satisfy a comparison.
                return False
            for v in cleaned:
                vl = _lc(v)
                if any(ch in v for ch in "*?"):
                    if fnmatch.fnmatch(fval, vl):
                        return True
                elif " " in vl:
                    if vl in fval:
                        return True
                elif fval == vl:
                    return True
            return False
        return pred2


def _compile_elastic_query(query: str, event_type_hint: str = "") -> tuple[Callable | None, str]:
    """Compile the common subset of EQL/KQL/Lucene into a matcher."""
    q = query.strip()
    m = re.match(r"^\s*\w+\s+where\s+", q, re.I)
    if m:
        q = q[m.end():]

    seq = re.match(r"^\s*(sequence|join)\b", q, re.I)
    if seq:
        m2 = re.search(r"\[(.*?)\]", q, re.S)
        if not m2:
            return None, "unparseable sequence"
        q = m2.group(1)

    toks = _lex_elastic(q)
    if not toks:
        return None, "empty query"
    parser = _EqlParser(toks)
    matcher = parser.parse()
    if matcher is None:
        return None, "no predicates parsed"
    return matcher, ""


def compile_elastic(doc: dict[str, Any]) -> tuple[Callable | None, str]:
    inner = doc.get("rule") if isinstance(doc.get("rule"), dict) else doc
    query = inner.get("query") or inner.get("eql") or inner.get("kql") or inner.get("lucene")
    if not query:
        return None, "no query (threat-match/esql-aggregation not supported)"
    lang = inner.get("language") or ""
    if lang == "esql":
        return None, "esql not supported"
    qtext = str(query)
    # Existence-only queries (``field:*`` joined by and/or): their real logic
    # joins against an enrich index. If the fields are threat-indicator ones
    # we now enrich events with, compile for real; otherwise they cannot
    # discriminate on a plain event stream — skip with a reason.
    stripped = re.sub(r"[\w.*@\-]+(?:\.[\w.*@\-]+)*\s*:\s*\*", " ", qtext)
    stripped = re.sub(r"\b(and|or|not)\b", " ", stripped, flags=re.I)
    if not stripped.strip(" \t\r\n()\"'"):
        # Threat-intel join rules: their enrich index is our TI store, which
        # event_doc exposes as threat.indicator.* fields. Rewrite only when
        # the queried existence fields are actually threat.indicator.* (or
        # the rule is a named TI indicator-match rule) — not when some other
        # dotted field merely contains the word "threat" (kibana signals).
        exist_fields = re.findall(r"([\w.*@\-]+(?:\.[\w.*@\-]+)*)\s*:\s*\*", qtext)
        ti_field = any(f.lower().startswith("threat.indicator") for f in exist_fields)
        title_l = str(doc.get("title") or "").lower()
        ti_rule = "threat intel" in title_l or "indicator match" in title_l
        if ti_field or ti_rule:
            return _compile_elastic_query("threat.indicator.matched.field:*")
        return None, "existence-only query (enrich-index rule)"
    if lang == "eql" or (isinstance(query, str) and re.match(r"^\s*\w+\s+where\b", query)):
        # sequence with `by` keys and >1 branch: stateless degrade to branch 1
        if re.search(r"sequence\b.*\[.*\]\s*(by|\.?where|\[)", query, re.I | re.S):
            m = re.search(r"\[(.*?)\]", query, re.S)
            if m and re.search(r"\]\s*(by|\[)", query[m.end():], re.I):
                return _compile_elastic_query("sequence " + m.group(0), "")
    return _compile_elastic_query(str(query))


# ---------------------------------------------------------------------------
# Wazuh compilation (from source XML)
# ---------------------------------------------------------------------------

def _wazuh_texts(node: ET.Element, tag: str) -> list[str]:
    out = []
    for el in node.iter(tag):
        if el.text:
            out.append(el.text.strip())
    return out


def compile_wazuh(doc: dict[str, Any], file_path: str | None) -> tuple[Callable | None, str]:
    """Wazuh rules are XML on disk; the catalog raw only carries group/level."""
    if not file_path or not os.path.exists(file_path):
        return None, "source xml missing"
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError:
        return None, "xml parse error"

    target_id = str(doc.get("rule_id") or doc.get("id") or "")
    if target_id.startswith("wazuh-"):
        target_id = target_id[len("wazuh-"):]
    rule_node = None
    for group in root.iter("group"):
        for rule in group.iter("rule"):
            if rule.get("id") == target_id:
                rule_node = rule
                break
        if rule_node is not None:
            break
    if rule_node is None:
        return None, "rule id not in xml"

    matchers: list[Callable[[dict], bool]] = []

    matches = _wazuh_texts(rule_node, "match")
    if matches:
        pats = [_m.lower() for _m in matches]
        def match_pred(d: dict) -> bool:
            hay = _lc(" ".join(str(d.get(k, "") or "") for k in ("message", "title", "payload", "data")))
            return all(any(re.search(p, hay) for p in [pat]) or pat in hay for pat in pats)
        matchers.append(match_pred)

    regexes = _wazuh_texts(rule_node, "regex")
    if regexes:
        compiled = [re.compile(r, re.I) for r in regexes]
        def regex_pred(d: dict) -> bool:
            hay = " ".join(str(d.get(k, "") or "") for k in ("message", "title", "payload", "data"))
            return any(c.search(hay) for c in compiled)
        matchers.append(regex_pred)

    ids = _wazuh_texts(rule_node, "id")
    if ids:
        idset = set(ids)
        matchers.append(lambda d: str(d.get("rule_id", "")) in idset)

    progs = _wazuh_texts(rule_node, "program_name")
    if progs:
        progl = [_p.lower() for _p in progs]
        matchers.append(lambda d: _lc(d.get("process_name", "")) in progl)

    if not matchers:
        groups = _wazuh_texts(rule_node, "group")
        if_group = _wazuh_texts(rule_node, "if_group")
        gl = [g.strip().lower() for g in groups if g.strip()]
        gl += [g.strip().lower() for g in if_group if g.strip()]
        if gl:
            def group_pred(d: dict) -> bool:
                # event groups live in message/tags; match on any label
                hay = _lc(" ".join(str(d.get(k, "") or "") for k in ("message", "title", "suricata_event_type", "index_name")))
                return any(g in hay for g in gl)
            matchers.append(group_pred)
        else:
            return None, "no matchable conditions (level-only rule)"

    def matcher(d: dict[str, Any]) -> bool:
        return all(m(d) for m in matchers)

    return matcher, ""


# ---------------------------------------------------------------------------
# Panther compilation (rule() from source file)
# ---------------------------------------------------------------------------

_PANTHER_BANNED = ("import os", "import sys", "subprocess", "__import__", "open(")


def compile_panther(doc: dict[str, Any], file_path: str | None) -> tuple[Callable | None, str]:
    """Exec the rule file's rule(event) in a restricted namespace.

    panther-analysis ships rule code as ``.py`` next to a ``.yml`` metadata
    twin; the catalog may point at either, so resolve the ``.py`` first.
    """
    if not file_path:
        return None, "source file missing"
    py_path = file_path
    if py_path.endswith((".yml", ".yaml")):
        candidate = py_path.rsplit(".", 1)[0] + ".py"
        if os.path.exists(candidate):
            py_path = candidate
    if not os.path.exists(py_path):
        return None, "source file missing"
    try:
        with open(py_path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return None, "source unreadable"

    low = src.lower()
    if any(b in low for b in _PANTHER_BANNED):
        return None, "source uses banned construct"

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None, "source syntax error"

    fn_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "rule":
            fn_node = node
            break
    if fn_node is None:
        return None, "no rule() function"

    # Extract ONLY the rule() function so module-level f-strings in helper
    # functions (title/alert_context) never reach exec.
    only_rule = ast.Module(body=[ast.fix_missing_locations(fn_node)], type_ignores=[])

    # Policy helpers Panther rules commonly use
    ns: dict[str, Any] = {
        "deep_get": lambda d, *keys, default=None: _deep_get(d, keys, default),
        "mask_string": lambda s: s,
        "uniq_list": lambda lst: list(dict.fromkeys(lst or [])),
        "type_name": lambda v: type(v).__name__,
        "daily_key": lambda *a, **k: "",
        "float_string": lambda v: str(v),
        "int_string": lambda v: str(v),
        "aws_strip_arn": lambda arn: arn,
        "aws_account_name": lambda aid: "",
        "to_string": lambda v: str(v),
    }
    try:
        exec(compile(only_rule, "<panther-rule>", "exec"),
             {"__builtins__": {"str": str, "int": int, "float": float, "bool": bool, "len": len,
                               "any": any, "all": all, "list": list, "dict": dict, "set": set,
                               "sorted": sorted, "True": True, "False": False, "None": None,
                               "isinstance": isinstance, "getattr": getattr, "lower": str.lower}},
             ns)
    except Exception as exc:
        return None, f"exec failed: {exc.__class__.__name__}"

    rule_fn = ns.get("rule")
    if not callable(rule_fn):
        return None, "rule() not callable"

    def matcher(d: dict[str, Any]) -> bool:
        try:
            return bool(rule_fn(d))
        except Exception:
            return False

    return matcher, ""


def _deep_get(obj: Any, keys: tuple[str, ...], default: Any = None) -> Any:
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            if k in cur:
                cur = cur[k]
            else:
                return default
        else:
            return default
    return cur


# ---------------------------------------------------------------------------
# Catalog compilation + evaluation entry point
# ---------------------------------------------------------------------------

class CompiledCatalog:
    """All matchable rules compiled once; evaluate() scores event batches."""

    def __init__(self) -> None:
        self.matchers: list[dict[str, Any]] = []
        self.skipped: list[dict[str, Any]] = []
        self.by_engine: dict[str, int] = {}
        self.skip_by_engine: dict[str, int] = {}

    def compile_from_rows(self, rows: list[dict[str, Any]]) -> "CompiledCatalog":
        """rows: dicts with rule_id, engine, title, severity, technique_ids, raw, file_path."""
        for row in rows:
            engine = (row.get("engine") or "").lower()
            if engine not in MATCHABLE_ENGINES:
                continue
            raw = row.get("raw")
            try:
                doc = json.loads(raw) if isinstance(raw, str) else (raw or {})
                inner = doc.get("raw")
                if isinstance(inner, str):
                    doc = json.loads(inner)
                elif isinstance(inner, dict):
                    doc = inner
            except (ValueError, TypeError):
                self._skip(engine, row, "raw unparsable")
                continue

            matcher: Callable | None = None
            reason = ""
            try:
                if engine == "sigma":
                    matcher, reason = compile_sigma(doc)
                elif engine == "elastic":
                    # Title lives on the catalog row (the unwrapped raw may
                    # not carry it); TI join rules key their rewrite on it.
                    matcher, reason = compile_elastic({**doc, "title": row.get("title", "")})
                elif engine == "wazuh":
                    # The unwrapped raw for wazuh carries only group/level;
                    # the id needed to find the <rule> node lives on the row.
                    if not doc.get("rule_id"):
                        doc = {**doc, "rule_id": row.get("rule_id", "")}
                    matcher, reason = compile_wazuh(doc, row.get("file_path"))
                elif engine == "panther":
                    matcher, reason = compile_panther(doc, row.get("file_path"))
            except Exception as exc:
                matcher, reason = None, f"compile crash: {exc.__class__.__name__}"

            if matcher is None:
                self._skip(engine, row, reason)
                continue

            # Degenerate-rule guard: a matcher that fires on a completely
            # empty event has no real condition (upstream ``return True``
            # stubs, passthrough rules bound to log sources we do not feed,
            # or a compile bug). Such a rule would alert on every event.
            try:
                if matcher(event_doc({})):
                    self._skip(engine, row, "degenerate: matches empty event")
                    continue
            except Exception:
                pass

            techs = row.get("technique_ids") or []
            if isinstance(techs, str):
                try:
                    techs = json.loads(techs)
                except ValueError:
                    techs = [t for t in re.split(r"[,\s]+", techs) if t]

            self.matchers.append({
                "rule_id": row.get("rule_id", ""),
                "engine": engine,
                "title": row.get("title", ""),
                "severity": (row.get("severity") or "medium").lower(),
                "technique_ids": techs,
                "description": row.get("description") or "",
                "match": matcher,
            })
            self.by_engine[engine] = self.by_engine.get(engine, 0) + 1

        return self

    def _skip(self, engine: str, row: dict, reason: str) -> None:
        self.skip_by_engine[engine] = self.skip_by_engine.get(engine, 0) + 1
        if len(self.skipped) < 400:
            self.skipped.append({
                "rule_id": row.get("rule_id", ""), "engine": engine, "reason": reason,
            })

    def evaluate(self, docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return one hit per (event, rule) pair that matched."""
        hits: list[dict[str, Any]] = []
        for ev in docs:
            doc = event_doc(ev)
            for m in self.matchers:
                try:
                    if m["match"](doc):
                        hits.append({
                            "event": ev,
                            "rule_id": m["rule_id"],
                            "engine": m["engine"],
                            "title": m["title"],
                            "severity": m["severity"],
                            "technique_ids": m["technique_ids"],
                            "description": m["description"],
                        })
                    else:
                        continue
                except Exception:
                    continue
        return hits


def load_catalog_from_store() -> CompiledCatalog:
    """Compile every matchable rule from the rules table."""
    from app_shared.unified_store import get_conn

    with_conn = get_conn()
    rows = with_conn.execute(
        "SELECT rule_id, engine, title, description, severity, technique_ids, file_path, raw "
        "FROM rules WHERE engine IN ('sigma','elastic','wazuh','panther')"
    ).fetchall()
    catalog = CompiledCatalog()
    catalog.compile_from_rows([dict(r) for r in rows])
    if catalog.by_engine.get("sigma") == 0 and catalog.skip_by_engine.get("sigma", 0) > 0:
        # compile_sigma raised on every row — surface the first real error
        first = next((s for s in catalog.skipped if s["engine"] == "sigma"), None)
        if first:
            logger.error("sigma compile failure sample: %s -> %s", first["rule_id"], first["reason"])
    return catalog
