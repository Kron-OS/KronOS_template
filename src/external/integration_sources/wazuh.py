"""WazuhPushSource: the first real, named-vendor ``IntegrationSource``
(roadmap Q2), reusing Q1's foundation.

**Real wire mechanism, verified against a real running manager, not assumed
from docs (CLAUDE.md SS F).** See ``poc/integration_source_wazuh/README.md``
for the full trail. Summary: Wazuh's ``wazuh-integratord`` daemon is
configured with one ``<integration>`` block in ``ossec.conf``
(``<name>custom-kronos</name>``, ``<hook_url>``, ``<api_key>``,
``<alert_format>json</alert_format>``) and, for every alert written to
``logs/alerts/alerts.json``, execs a shell script matching ``<name>`` in
``/var/ossec/integrations/`` with argv ``[alert_file, api_key, hook_url,
options_file, debug_flag]`` (this exact argv shape confirmed by reading
``wazuh/wazuh-manager:4.14.7``'s own bundled ``slack.py``, which hardcodes
``WEBHOOK_INDEX = 3``, inside the running container). There is no built-in
generic "POST this alert to my own arbitrary hook_url" script the way the
roadmap's own SS0 research summary implied -- ``hook_url``/``api_key`` are
just two of the three argv strings integratord always passes; only the
five vendor-named built-ins (slack/pagerduty/shuffle/virustotal/maltiverse)
ship a script that already knows what to do with them. A ``custom-*`` name
requires supplying that script yourself -- this PoC's
``poc/integration_source_wazuh/custom-kronos{,.py}`` is exactly that
script, and it is the thing that actually performs the real HTTP POST of
the raw alert JSON to KronOS's push endpoint with the shared API key in
the ``X-KronOS-Source-Key`` header ``StaticApiKeyInboundAuthenticator``
expects. This module (``WazuhPushSource``) is the KronOS-side half: it
only ever sees one already-POSTed alert body per call.

**Pinned-version correction, reported not silently applied (CLAUDE.md SS F
"fail loudly").** ``docker/wazuh/docker-compose.wazuh.yml`` pins
``wazuh-manager:5.1.0`` and says "Must use Wazuh >=5.1" because of a 5.0
data-destruction bug. Verified 2026-08-09 against the real Docker Hub tag
list (65 tags) and the real Wazuh GitHub Releases API: **no ``5.1.0`` tag
exists anywhere** -- the newest published image is ``5.0.0-beta4``, and the
current real *stable* release is ``4.14.7``. The flagged bug is real
(GHSA-ff9g-85jq-r3g3, a CVSS-10 OpenSearch-bulk-injection issue in 5.0's
new ``inventory_sync`` subsystem, affecting ``5.0.0-beta1``-``beta2``,
patched in ``5.0.0-beta3``) -- so "avoid 5.0.0-beta1/beta2" is the real,
narrower version of the repo's comment. Separately and more importantly for
this module: a real, direct inspection of ``wazuh/wazuh-manager:5.0.0-beta4``
found Wazuh 5.x has already replaced ``ossec.conf``/``wazuh-integratord``
entirely (config is now ``/var/wazuh-manager/etc/wazuh-manager.conf`` under
a ``<wazuh_config>`` root element, no ``wazuh-integratord`` binary exists at
all, and outbound alerting appears to have moved to a new, undocumented
YAML "engine outputs" mechanism -- ``etc/outputs/default/
file-output-integrations.yml``). Since this whole roadmap item is
specifically about ``wazuh-integratord``'s real, documented mechanism, this
module and its PoC were verified against ``wazuh/wazuh-manager:4.14.7``
(the current real stable release, predates the 5.0 CVE entirely since that
subsystem did not exist yet) rather than either the nonexistent ``5.1.0``
or a 5.x beta whose integration mechanism has already changed underneath
this design. See this PoC's own README for the full reasoning; flagged to
the orchestrator for a decision on updating ``docker/wazuh/`` itself
(out of this module's scope -- that compose file is dormant infra config,
not this connector's own code).
"""

from __future__ import annotations

import json
import logging

from src.application.integration_source import IntegrationSource
from src.domain.integration_source import IntegrationDeliveryMode
from src.exceptions import ParsingError

logger = logging.getLogger(__name__)

# A real Wazuh alert (any rule, any decoder) always carries at least these
# two top-level keys -- verified against a real captured alert (see
# poc/integration_source_wazuh/output.txt), not guessed: `rule` (the fired
# rule's own level/description/id/groups/mitre mapping) and `timestamp`
# (ISO-8601 with a numeric UTC offset, e.g. "2026-08-09T04:02:30.663+0000").
_REQUIRED_ALERT_KEYS = ("rule", "timestamp")


class WazuhPushSource(IntegrationSource):
    """PUSH source for Wazuh's ``wazuh-integratord`` custom-integration
    webhook (roadmap Q2).

    One HTTP POST body == exactly one real Wazuh alert JSON object --
    ``wazuh-integratord`` invokes its configured integration script once per
    alert line in ``alerts.json`` (real, observed behavior, not assumed),
    and this PoC's own ``custom-kronos.py`` script forwards each invocation
    as its own POST. Unlike ``GenericWebhookPushSource``, this class does
    **not** unwrap a ``{"events": [...]}`` batch envelope -- Wazuh's real
    wire shape has no such envelope, and silently accepting one would risk
    masking a real malformed/foreign payload as a legitimate empty batch.
    """

    @property
    def source_type(self) -> str:
        return "wazuh"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.PUSH

    async def parse_push_event(self, raw_body: bytes) -> list[bytes]:
        """Validate *raw_body* is one real Wazuh alert JSON object.

        Raises :class:`~src.exceptions.ParsingError` (CLAUDE.md invariant
        #8 -- fail loudly) if the body is not JSON, is not a JSON object, or
        is missing both fields every real Wazuh alert carries -- a
        misconfigured ``hook_url`` pointed at the wrong ``source_type`` route
        should be a loud, observable failure, not a silently-accepted
        opaque event.
        """
        try:
            decoded = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParsingError(
                "Wazuh push body is not valid JSON",
                context={"source_type": self.source_type, "error": str(exc)},
            ) from exc

        if not isinstance(decoded, dict):
            raise ParsingError(
                "Wazuh push body did not decode to a JSON object",
                context={"source_type": self.source_type, "decoded_type": type(decoded).__name__},
            )

        missing = [key for key in _REQUIRED_ALERT_KEYS if key not in decoded]
        if missing:
            raise ParsingError(
                "Wazuh push body is missing required alert field(s) -- "
                "not a real Wazuh alert (alert_format=json) payload",
                context={"source_type": self.source_type, "missing_fields": missing},
            )

        return [raw_body]
