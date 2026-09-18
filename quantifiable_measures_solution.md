# Quantifiable Measures of the Implemented Solution

## Response engine and warning quality

- **Warning level coverage:** every alert now emits `warning_level` (`low|medium|high|critical|unknown`) and normalized `severity_score` (0-100).
- **Low-level response transparency:** low-severity previews force a minimal `observe_only` path and expose the exact command in `response_preview.preview_command`.
- **Critical-path containment depth:** critical responses now trigger real honeypot deployment (`scripts/deploy_honeypot.py`) with:
  - container/session identifiers,
  - persisted docker log path,
  - persisted traffic capture path,
  - optional Groq analysis artifact.

## Persistence and forensic traceability

- **Response execution journal:** response actions are persisted in `state/response/actions.jsonl` and indexed into `security-response-*`.
- **Honeypot artifact persistence:** each critical session stores:
  - `state/honeypot/sessions/<session_id>/docker.log`
  - `state/honeypot/sessions/<session_id>/traffic.jsonl`
  - `state/honeypot/sessions/<session_id>/session.json`
  - append-only session index `state/honeypot/sessions.jsonl`

## Detection and log usability

- **Bundled log quality:** grouped log API now aggregates by normalized signature across the result window (not just consecutive adjacency), increasing repeat-event bundling reliability.
- **Chat response grounding:** `/api/chat` now answers from live rules/logs/alerts context and returns machine-usable references for operator pivots.

## Operator UX measurables

- **Time precision controls:** sidebar now uses exact date+time selectors (`date` + `time` inputs for From/To) instead of quick presets.
- **Playbook clarity:** playbook view now shows technique count, linked detection count, selected playbook metadata, and related live detections with command previews.
- **Severity visibility:** dashboard/response surfaces display normalized severity levels and warning levels directly.
