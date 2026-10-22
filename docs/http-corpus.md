# Deterministic HTTP fixture generator

Run `python3 tools/http_corpus.py --output tests/generated-http` to generate five **synthetic header-only** HTTP requests plus ground-truth labels.

The labels describe whether a *simple large POST to a PHP route* heuristic should trigger, not whether a request represents PHP2Shell exploitation. Two are large PHP routes, one large non-PHP route, and two small PHP routes. All hosts use `example.invalid`. No network requests are sent.

These fixtures can test a future offline parser and documentation examples. **They are not valid TCP replays or PCAPs:** they have no bodies, and their declared Content-Length is intentionally not fulfilled. Native detection efficacy on packet capture is *not* demonstrated.

No malicious payloads, credentials or real production traffic are stored.
