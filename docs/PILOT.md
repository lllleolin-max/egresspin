# Actual laboratory pilot and limits

Exact ordinary-installed27d1f9a0b61927a76a275035512e748c5e8eef2d runtime; five
modules unchanged in subsequent probe/docs commits. Reproduce with probes/pilot.py
and probes/workflow_cost.py. Exact hashes, complete files and raw invocation records
are external implementation/egresspin evidence. These are builder runs, not
independent network re-executions or production demand/customer savings.

Correct mature baseline: curl8.21.0/Schannel, RESOLVE, independent origin/all-address
policy before every hop, no automatic-L, --disable to exclude curlrc, --noproxy '*',
verifying public synthetic LAB CA/hostname. Windows --ssl-no-revoke matches
Python default no-CRL/OCSP, while certificate/hostname verification stays enabled.
Both modes get the same per-case origins/address schedule/body/redirect header
rules. Curl already implements the mature pinning/TLS primitives.

10shapes×3repetitions×2modes=60 actual cases, 2026-10-04 23:42:46–23:42:56 UTC,
pilot-native-peers-bda37: small,1000orders, changing DNS, mixed A/AAAA, relative,
cross-origin header stripping, denied redirect, valid TLS, TLS relative and wrong
hostname. All60 answers/refusals equivalent:66 native HTTP requests,24 native TLS
handshakes,36 curl processes. A product-free native consumer reads all42 whole
bodies/36000order records and every file/hash. Each33787B order body SHA256
d048015367919cece77275cab95ef1ddef77e83daed151e0a4a60708687ab0dc contains48474500cents.
Cross-origin Authorization/Cookie/X-Api-Key are absent at the actual second
receiver. Native listener/peer/SNI are retained in both TLS modes; failed-hostname
Schannel stats omit remote_ip, so the native witness supplies that observation.

| Shape | SDK median ms | curl median ms | Useful result |
|---|---:|---:|---|
| Small | 19.6400 | 57.7342 | Same32B; no correctness benefit |
| Orders | 5.1041 | 56.0920 | Same complete1000orders |
| Changing DNS | 19.4691 | 52.5914 | Both one lookup, forbidden0 |
| Mixed A/AAAA | 2.0680 | 0.0355 | Both refuse before connect; SDK more costly |
| Relative | 22.3313 | 105.0389 | Same two-hop result |
| Cross-origin | 13.8901 | 105.9665 | Both strip sensitive caller headers |
| Denied redirect | 15.9782 | 47.9772 | Both refuse; first GET already occurred |
| Valid TLS | 26.1922 | 117.1034 | Same verified answer |
| TLS relative | 11.0288 | 210.7651 | Same verified two-hop answer |
| Wrong hostname | 5.8924 | 71.2573 | Both refuse, actual HTTP0 |

Three samples, noisy ranges and the more expensive SDK refusal all remain.
Wall times include SDK context preparation and actual curl process spawning;
this is not an in-process libcurl comparison or an algorithmic speedup.
Shared fixture setup4968939500ns is charged separately once. The initial60-case
run and partial harness failure remain; this peer-observation run does not erase
them. An explicitly weaker URL-only+ordinary connector performs a second changed
DNS lookup and an actual GET to the owned forbidden listener; full returned bytes
are kept. That is separate from the mature equivalent baseline, not enough by
itself to establish innovation.

workflow-cost-27d adds6 complete actual HTTP→SQLite→saved-key reuse→native JSON
consumers. Correct curl+native transactional sink and SDK both get one HTTP/DNS
request, one durable row and no repeat GET. Both prepare12288B and finish45056B/
11pages. Median total SDK45.6974ms versus baseline58.9284ms, but SDK preparation
19.0310ms versus2.3096ms costs more. All samples/prepare/network-commit/metadata
are retained (SDK audit279B versus baseline about2188B; different metadata shapes
are not evidence of a better algorithm). Adoption/paid demand/revenue are unknown.

resources-interrupt-27d consumes1MiB input/export/native SQL, body/sink caps±1,
zero-body, DNS+1, item0 preflight, deadline, redirect0/1. Actual interpreterPID289656
(launcher286228) killed after partial HTTP/before commit:0native rows; public
reopen precedes native oracle, retryGET2 yields one complete1MiB row.
extra-boundaries-27d covers response headers1055B exact/minus1, request8192B exact/
+1 and32/+1 count, actual IPv6::1 and failedAAAA→validatedA fallback. Actual
interpreterPID319908 (launcher333980) killed after commit:1native full row, public
reopen/retry with0 new GET. GET effects cannot be rolled back; no HTTP exactly-once.

Finite trusted-host/admin policy, not auth gateway or universal SSRF certificate.
No hostile-filesystem defense, hard RSS, DNS preemption, gzip inflation or universal
HTTP grammar. Independent review, four-job CI and exact public delivery pending.
