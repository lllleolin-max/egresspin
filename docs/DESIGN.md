# Finite supported contract

Trusted application code supplies immutable policy, bounded resolver and headers.
The local CLI caller controls policy and SQLite path; it is not an untrusted
HTTP gateway or authentication layer. Only GET with HTTP/HTTPS, ASCII DNS labels
or canonical IPv4/IPv6, ports1–65535, ASCII URI path/query with valid percent
escapes. DNS IDNA/punycode, userinfo, fragments, zones, backslashes and alternate
numeric host spellings are refused. Origin allowlist is exact normalized scheme,
host and effective port; no wildcard/suffix authority. IPv4-mapped addresses
normalize to IPv4 before address policy or connection. All DNS answers must pass;
a mixture of permitted and denied addresses refuses the entire hop before any
connection. System resolver is called once per hostname hop, then numeric socket
connect has no second lookup. Literal IPs need no DNS lookup. IPv4/IPv6 family is
selected from that validated numeric address. Fallback tries only validated answers
in order within the attempts budget. TCP peer must equal the chosen address.

HTTPS uses a default verifying SSLContext (minimum TLS1.2), original canonical
hostname as SNI, and its certificate hostname validation; a trusted optional CA
file does not disable hostname checks. TLS failure may fall back only to another
already validated address. Certificate/transport failure records a private code
and actual observed TCP peer where a connection was made. No request goes through
environment proxies. OS routing, compromised resolver/CA/host, transparent proxies
outside this process and remote URL content are not authenticated by this library.

Caller headers:32maximum,8192serialized bytes, ASCII tokens/printable values,
case-duplicate/reflected Host/connection/framing/proxy fields refused. Each
redirect301/302/303/307/308 is interpreted explicitly, relative references are
joined against the current URL and checked again. All origins must already be
allowed; all DNS answers are freshly verified. On an origin change only accept,
accept-language and user-agent survive, including scheme/port changes; custom
API keys, authorization and cookies are removed. The client never stores cookies.
Every actual hop has a witness with URL SHA256, canonical origin, answers,
attempts, peer, status, bytes, elapsed ns and outcome. It does not log full query
or request headers. GET side effects already made by a server are not rolled back
by a later redirect refusal, response failure or killed importer.

Defaults:URL8192ASCII bytes, body1048576bytes/response, accepted serialized
headers32768bytes, DNSanswers16 (max64), connect attempts4/hop (max16), redirects4
(max16), total network deadline5000ms (max60000). Thus HTTP calls≤redirects+1 and
body bytes retained per hop≤bodycap; redirect bodies are bounded then discarded.
Response headers first pass the standard http.client parser, whose bounded
scratch permits at most100 lines with a65536byte line limit before the smaller
configured aggregate check. This is not a hard RSS guarantee or an early-wire
header quota. Fixed metadata/serialization/TLS/socket buffering add memory beyond
raw body bytes. Content-Length is ASCII decimal, large leading zeros accepted
without unbounded integer conversion by policy checking, duplicate length and
TE+length refused; only ordinary close/length or chunked framing is supported.
Chunk sizes require hexadecimal digits and chunk-data delimiters require CRLF.
Valid leading zeros, uppercase hex and ignored extensions remain accepted. The
narrow framing guard uses HTTPResponse's private helpers, checked against CPython
3.11 and3.14 source; future changes require actual wire probes. This is not a
claim to implement every HTTP grammar or trailer semantic.
Content encodings are stored raw; no gzip inflation occurs.
Non-final informational responses other than standard100continue are explicitly
unsupported and refused; WebSocket upgrades and103EarlyHints are not interpreted.
Redirect Location must be a nonempty bounded ASCII URI-reference without spaces
or control characters before it is joined, and then the resulting URL is rechecked.
The socket's file reader resets each receive timeout from a monotonic whole-fetch deadline, so
slow socket reads do not receive a fresh per-hop time budget. Blocking system
getaddrinfo cannot be preempted by the stdlib; its result is rejected if the deadline
has elapsed, but DNS can make caller wall time longer. A custom resolver is a
trusted integration that must also finish and yield bounded values. No thread
pool/parallel network requests or automatic retry is hidden in the API.

ImportStore is a trusted cooperative SQLite application file, not a safe arbitrary
foreign-file converter. Default1000 items/max10000, total raw bodies16MiB/max160MiB;
metadata, journals and pages cost extra and are not a disk quota. Request identity
hash binds normalized URL and sorted validated headers without storing header
values. The original caller mapping is observed once and the same private snapshot
supplies both identity and the sent request. Existing same-key/same-identity returns its immutable saved snapshot;
changed identity rejects. A new fetch completes outside the SQLite transaction,
then INSERT of body/hash/audit commits atomically, quotas/conflict rechecked under
BEGIN IMMEDIATE. Different concurrent results do not overwrite each other. GET
can happen twice, and death after remote GET/before commit leaves no sink row.
SQLite transaction rollback preserves an existing committed row. Export consumes
and checks complete stored bytes; content is opaque to the product. Sink paths,
CA file and policy are administrator-owned; malicious filesystem replacement,
foreign schemas, host compromise, authentication and backups/privacy need a
separate application boundary. No claimed cross-filesystem or HTTP exactly-once.

Prior art, primary pages actually consulted2026-10-04 UTC:
[OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html),
[libcurl RESOLVE](https://curl.se/libcurl/c/CURLOPT_RESOLVE.html),
[Python SSL verification](https://docs.python.org/3/library/ssl.html).
OWASP discusses origin/IP allowlists and redirect risk; libcurl already pins
resolved addresses while retaining the URL identity; verifying TLS is mature.
Potential useful difference here is auditable per-hop pin/policy/body-import
evidence with independently observed listeners, not invention of those primitives.
Correct mature curl RESOLVE plus explicit per-hop same policy remains a required
equivalent control; a weaker URL-only client cannot be the only competitor.

[RFC 9112 chunk framing](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1)
and official [CPython3.11](https://raw.githubusercontent.com/python/cpython/3.11/Lib/http/client.py)
and [3.14 HTTP client source](https://raw.githubusercontent.com/python/cpython/3.14/Lib/http/client.py)
were consulted for the third-round malformed-framing finding. Existing numeric
socket/TLS/HTTP/SQLite mechanisms are integrated; DNS pinning, secure redirects,
idempotent snapshots and SSRF prevention are not claimed inventions.
