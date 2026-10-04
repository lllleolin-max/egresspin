# Actual iteration record

GPT-6.1-Sol / Ultra implementation writer; separate read-only independent reviewer.
Evidence paths below refer to the portfolio's implementation/egresspin packet.
No independent PASS or score is claimed. Initial features, no-findings, docs
and harness fixes are not repair cycles.

Initial complete SHA 8b1eace959601130f6d7439a7d65d10f86ab3be5:
baseline-ordinary/result.json, 2026-10-04 23:23:29–23:24:05 UTC. Ordinary wheel,
five Git-LF/archive/wheel/isolated-site byte associations,16tests, actual HTTP/TLS,
native SQLite/full registered CLI consumer, example and pipcheck PASS.

1. Before8b1eace959601130f6d7439a7d65d10f86ab3be5, explicit :0 became port80
   through a truthiness default. Owned127.0.0.9:80 actually received an invalid GET
   and DNS call despite the original ports1–65535 contract. Repair2057f26774debf1317dd06093d9d995bf323b2c4
   distinguishes absent port from zero before range checking. Unchanged port_zero.py
   SHA256 d7d478a73ee244666ab905359988e61e3d09785043ecaa8f289294a30d63310d:
   port-zero-before-8b1.record.json exit1 → round1-port-zero/result.json probe0
   exit0, invalid DNS/GET0, valid default80 still receives complete42B.
2. Before2057f26774debf1317dd06093d9d995bf323b2c4, an accepted dict subclass
   and actual separate caller mutation between two observations bound the first
   headers but sent the second. Native HTTP request digest differed from stored
   identity; full90B was stored. Repaircbd644831e2122511787fb3ab824199a5cf152b6
   observes once and uses the same private plain mapping for identity and request.
   Unchanged header_identity.py SHA256 7f02e4c8278d8c51de535d48b8b776b3172178410769639ca3a9589839ad5733:
   header-identity-before-205.record.json exit1 → round2-header-identity/result.json
   probe0 exit0, one observation, actual/native digest equal, full89B consumed.
   The observation hook makes an accepted mapping's schedule deterministic; no
   product function is patched. Independent support-domain classification remains
   pending; this is not uncontrolled race stress coverage.
3. Beforecbd644831e2122511787fb3ab824199a5cf152b6, four actual malformed
   chunk packets (+HEX,0xHEX,underscore,non-CRLF data delimiter) were accepted200
   and each created a sink row. Repair27d1f9a0b61927a76a275035512e748c5e8eef2d
   adds a narrow hexadecimal/CRLF guard around stdlib buffering.
   Unchanged chunk_framing.py SHA256 12190861fad0ed4331e22ba5e40af708e9de2a6b72e0841f9f5feac758d7e1a3:
   chunk-framing-before-cbd.record.json exit1 → round3-chunk-framing/result.json
   probe0 exit0, malformed responses private-refused/0rows, valid leading-zero/
   uppercase/extension complete50B/951cent JSON retained. A negative size already
   refused before, and is a no-benefit case. Malformed packets decoded correct
   JSON; their defect is prohibited framing, not fabricated data corruption.

Every after stage also builds/installs an ordinary wheel, associates five modules,
runs16tests/example/registered CLI/pipcheck, and retains the preceding original
probes. Exact commands, UTC times, raw logs and full bytes are in external HANDOFF.
Postrepair60case same-policy curl, native TLS peer/SNI, complete consumer, quotas
and two actual killed interpreters use the exact installed27d runtime.
294a6a4a7ea731fbe9b2fda736401eacb61214ef and bda37f9f9321f58595cdecd6a0452cf5a224d5d5
are source-probe additions; runtime modules remain identical and no round is added.

Method failures are preserved: initial pilot bytes/string Location key mismatch;
completed60-case subject exit0 followed by outer GBK stdout/stderr rendering error;
then stray wrapper indent preventing a resource subject from running at all.
Later actual successful invocations have separate records. None count as product
findings or rounds. Expected native TLS ConnectionResetError after wrong-hostname
rejection remains in raw receiver logs. No push/tag/release/actual public CI is
attributed to this agent; new supported counterexamples remain eligible for repair.
