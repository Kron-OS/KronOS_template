#!/usr/bin/env python3
# Real custom wazuh-integratord Python integration -- forwards one Wazuh
# alert (already alert_format=json on disk, one alert per invocation, real
# wazuh-integratord behavior confirmed by direct observation of this PoC's
# own captured output.txt) verbatim as raw bytes to KronOS's real
# IntegrationSource PUSH endpoint.
#
# ossec.conf configuration structure (see this dir's README.md for why
# 'custom-' prefix + this script's own existence is required -- Wazuh's
# integratord only auto-POSTs for the vendor-specific built-in names
# (slack/pagerduty/shuffle/virustotal/maltiverse), not for an arbitrary
# hook_url):
# <integration>
#   <name>custom-kronos</name>
#   <hook_url>http://kronos-poc-wazuh-receiver:8000/api/integrations/push/wazuh</hook_url>
#   <api_key>API_KEY</api_key>
#   <alert_format>json</alert_format>
# </integration>
#
# Real argv shape confirmed by reading wazuh/wazuh-manager:4.14.7's own
# bundled /var/ossec/integrations/slack.py (WEBHOOK_INDEX = 3) inside the
# running container -- not assumed from memory:
#   argv[1] = path to a temp file containing exactly one JSON alert
#   argv[2] = <api_key> from the <integration> block
#   argv[3] = <hook_url> from the <integration> block
#   argv[4] = options file path (unused here)
#   argv[5] = 'debug' if wazuh-integratord was run with debug enabled

import json
import os
import sys

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

ALERT_INDEX = 1
APIKEY_INDEX = 2
HOOK_URL_INDEX = 3

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{pwd}/logs/integrations.log"


def debug(msg: str) -> None:
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")


def main(args: list[str]) -> int:
    if len(args) < 4:
        debug(f"# ERROR: custom-kronos wrong arguments: {args}")
        return 2

    alert_file_location = args[ALERT_INDEX]
    api_key = args[APIKEY_INDEX]
    hook_url = args[HOOK_URL_INDEX]

    try:
        with open(alert_file_location) as f:
            raw_alert_bytes = f.read().encode("utf-8")
            json.loads(raw_alert_bytes)  # validate it is real JSON before forwarding
    except Exception as exc:
        debug(f"# ERROR: could not read/parse alert file {alert_file_location}: {exc}")
        return 6

    try:
        response = requests.post(
            hook_url,
            data=raw_alert_bytes,
            headers={
                "Content-Type": "application/json",
                "X-KronOS-Source-Key": api_key,
            },
            timeout=10,
        )
        debug(
            f"# custom-kronos POST {hook_url} -> status={response.status_code} "
            f"body={response.text[:500]!r}"
        )
    except Exception as exc:
        debug(f"# ERROR: POST to {hook_url} failed: {exc}")
        return 7

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
