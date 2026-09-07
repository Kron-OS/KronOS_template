# custom_container.log — provenance

## Image

`redis:7-alpine` (Redis 7.4.9, per the log's own `Redis version=7.4.9`
line) — a small (57.8 MB), real, freely-pullable image already cached
locally on this host. Chosen as a stand-in for "logs from a custom
container running an app that isn't one of KronOS's already-supported
formats" (nginx/apache access logs, Suricata EVE JSON, AWS CloudTrail,
Windows EVTX) — Redis emits its own bespoke line-oriented startup log, not
any of those.

## How it was captured

```
docker run -d --name kronos-poc-redis-logsample redis:7-alpine
sleep 3
docker logs kronos-poc-redis-logsample > custom_container.log
docker stop kronos-poc-redis-logsample
docker rm kronos-poc-redis-logsample
```

Container ran for ~3 seconds (just long enough to reach "Ready to accept
connections"), was stopped and removed immediately after capture. No other
containers on this host were touched (checked `docker ps` before starting;
this project's own `docker-redis-1` long-lived container was left
untouched — this was a separate, distinctly-named throwaway container).

## Log format (one-line description)

Redis's native startup log format: `<pid>:<role-char> <DD Mon YYYY>
<HH:MM:SS.mmm> <level-char> <message>` — e.g. `1:M 07 Sep 2026
22:43:22.920 * Server initialized`, where role is `C` (config-loading
process) or `M` (master), and level is `.`/`-`/`*`/`#` (debug/verbose/
notice/warning). No JSON, no structured key=value scheme, no timestamp
timezone — a genuine bespoke plaintext format, real captured stdout from a
real container run (not fabricated).
