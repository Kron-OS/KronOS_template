# PoC: `src/adapter/opensearch/client.py` against a real OpenSearch 2.11.1

## Versions (pinned, read from this repo — not assumed)
- Server: `opensearchproject/opensearch:2.11.1` (`docker/docker-compose.dev.yml`)
- Client library: `opensearch-py>=2.6` (`pyproject.toml`) — pip resolves this
  unbounded constraint to **3.2.0** as of this run.

## What this actually does
`run_poc.py` imports the **real** `OpenSearchClient` class from
`src/adapter/opensearch/client.py` — not a reimplementation — and calls each
of its public methods against a real, disposable OpenSearch container
(`kronos-poc-opensearch`, security plugin disabled, same as dev compose).

Run:
```
docker run -d --name kronos-poc-opensearch \
  -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -p 19200:9200 -p 19600:9600 opensearchproject/opensearch:2.11.1

source ~/venv/bin/activate
pip install "opensearch-py[async]>=2.6"
python poc/opensearch/run_poc.py
```

## Real findings (captured in `output.txt`)

1. **Bug — missing `[async]` extra.** `pyproject.toml` declares
   `"opensearch-py>=2.6"` (no extra). `OpenSearchClient.__init__` does
   `from opensearchpy import AsyncOpenSearch`. In opensearch-py 3.x, the
   async client requires `aiohttp`, which only installs via the
   `opensearch-py[async]` extra. **A plain `pip install .` of this repo
   installs a version of the dependency that makes every code path through
   `OpenSearchClient` raise `ImportError: cannot import name 'AsyncOpenSearch'`
   at first use.** Confirmed by reproducing the exact `ImportError` with only
   the bare dependency installed, then resolving it by adding the extra.
   **Fix needed:** change `pyproject.toml` to `"opensearch-py[async]>=2.6"`.

2. `ensure_index_template()` — works as written against a real 2.11.1 node.

3. `ensure_ism_policy()` — works as written (first call; the code's own
   comment about tolerating a 409 on repeat calls was not re-tested here,
   only the empty case, which is the failure this repo's comment predicted).

4. **Gap — `ensure_tenant_role()` cannot succeed in dev mode.** With
   `DISABLE_SECURITY_PLUGIN=true` (the pinned dev config), OpenSearch does
   not register the security plugin's REST handlers at all, so
   `PUT /_plugins/_security/api/roles/...` returns
   `400 no handler found for uri [...] and method [PUT]` — not a 200, not a
   409, an entirely different error shape than the code's `ConflictError`
   handling anticipates elsewhere. This means `ensure_tenant_role()` has
   **never been exercised successfully in the dev stack as configured**, and
   there is no automated test path today that would catch a real regression
   in it short of running a real cluster with the security plugin enabled
   (i.e. closer to prod config).

5. `bulk_index()` — works: indexed 1/1 doc, doc round-tripped via `GET`
   with all nested `event.*` / `host.*` / `kronos.*` fields intact, and was
   found by `search(match_all)`. The index template's mappings did not
   reject any field in the test document.

See `output.txt` for the raw captured run.
