# EgressPin

Import an explicitly allowed HTTP(S) URL using the same IP address that passed
your DNS policy. EgressPin connects a numeric address directly, checks the TCP
peer, preserves the original Host/TLS SNI and verifies the original certificate
hostname. Each redirect repeats URL/origin/DNS/address checks. A concrete SQLite
sink commits the complete response and connection witness together, and exports
the original bytes for a real consumer.

Python3.11+; MIT; standard-library runtime. This is a finite trusted-host URL
import library and local administrator CLI, not a universal SSRF certification.
URL/DNS pinning and per-hop policies are existing practices; see [DESIGN](docs/DESIGN.md).

```powershell
python -m pip install .
python -I examples/workflow.py
egresspin import https://example.com/orders --key daily --database imports.sqlite --policy policy.json
egresspin export --key daily --database imports.sqlite > orders.json
```

The example runs a real local HTTP listener and consumes all1000 order records
through SQLite and an independent native JSON/integer consumer. Example policy
for a real trusted public origin (replace it with your actual service):

```json
{"allowed_origins":["https://example.com"],"max_body":1048576,"timeout_ms":5000}
```

SDK: `Fetcher(Policy(("https://example.com",))).fetch(url)` returns immutable
status/body/content type/final URL/per-hop evidence. `ImportStore(path).import_url`
accepts only a200 response and stores full bytes plus witness atomically. A stable
key binds the normalized original URL and normalized request headers; a repeated
identical import returns the saved snapshot without another HTTP request. Changed
identity is refused. Concurrent same-identity requests can both perform GET; their
different bodies conflict rather than overwrite. HTTP GET is not an exactly-once
network effect guarantee, and no remote content authenticity beyond HTTPS server
identity is inferred.

Configuration is trusted application data. Exact scheme/host/port origin rules;
ASCII DNS names and canonical IPs; no credentials, fragments, IDNA/punycode,
zone identifiers, arbitrary protocols or ambient proxies. Every DNS answer must
pass. Defaults deny loopback/private/link-local/metadata/multicast/non-global
addresses. `testing_ips` is an explicit exact-address laboratory override, never
a production default. Cross-origin redirects retain only accept/accept-language/
user-agent and strip every other caller header. Response bytes are raw decoded
HTTP framing, not automatically decompressed.

Limits are declared in DESIGN, including OS DNS blocking, standard HTTP parser
scratch space, trusted cooperative SQLite files, quotas and interruption scope.
CLI errors expose private reason codes and network witness, never request header
values. Audit holds URL digests and origin, not query contents. SQLite explicitly
stores the source URL and full imported content; secure deletion/privacy is not a
claim. Public test-only TLS key/cert under tests/fixtures are deliberately known,
synthetic and unsuitable for real credentials. Generation used cryptography as
one-time tooling; ordinary runtime/testing does not require it.

`python -I -m unittest discover -s tests -v` tests actual HTTP/TLS listeners,
hostname/SNI, changed DNS, fallback, mapped IPs, redirects/header stripping,
refusals, whole bytes, native SQL and the registered console. Configured CI is
Ubuntu/Windows Python3.11/3.14; final successor execution/public delivery is pending. Four actual
postbaseline repairs and unchanged ordinary-wheel FAIL-to-PASS probes are recorded
in [ITERATIONS](docs/ITERATIONS.md). The [pilot](docs/PILOT.md) keeps equivalent
correct curl results, complete native consumers, preparation costs and a slower
simple rejection. C/T/I and independent engineering assessment remain unscored;
the original719 builder prepublication score85.20 remains historical, below95.
The later current-IANA correction is separately evidenced and not a claim of
live classification or global SSRF certification; see DESIGN update procedure.
