"""Unit tests for WazuhPushSource (roadmap Q2).

``_REAL_CAPTURED_ALERT`` below is the exact JSON body real
``wazuh-integratord`` (wazuh/wazuh-manager:4.14.7) POSTed to KronOS's real
push endpoint during ``poc/integration_source_wazuh/``'s own real end-to-end
run (see that directory's ``output.txt``) -- not a hand-crafted guess at
Wazuh's schema.
"""

from __future__ import annotations

import json

import pytest

from src.domain.integration_source import IntegrationDeliveryMode
from src.exceptions import ParsingError
from src.external.integration_sources.wazuh import WazuhPushSource

_REAL_CAPTURED_ALERT = (
    b'{"timestamp":"2026-08-09T04:07:46.692+0000","rule":{"level":5,'
    b'"description":"sshd: Attempt to login using a non-existent user",'
    b'"id":"5710","mitre":{"id":["T1110.001","T1021.004"],'
    b'"tactic":["Credential Access","Lateral Movement"],'
    b'"technique":["Password Guessing","SSH"]},"firedtimes":2,"mail":false,'
    b'"groups":["syslog","sshd","authentication_failed","invalid_login"],'
    b'"gdpr":["IV_35.7.d","IV_32.2"],"gpg13":["7.1"],"hipaa":["164.312.b"],'
    b'"nist_800_53":["AU.14","AC.7","AU.6"],'
    b'"pci_dss":["10.2.4","10.2.5","10.6.1"],'
    b'"tsc":["CC6.1","CC6.8","CC7.2","CC7.3"]},'
    b'"agent":{"id":"000","name":"4b29f98ecc3d"},'
    b'"manager":{"name":"4b29f98ecc3d"},"id":"1786248466.704409",'
    b'"full_log":"Aug  9 06:07:46 4b29f98ecc3d sshd[9911]: Failed password '
    b'for invalid user postgres from 198.51.100.7 port 44321 ssh2",'
    b'"predecoder":{"program_name":"sshd","timestamp":"Aug  9 06:07:46",'
    b'"hostname":"4b29f98ecc3d"},"decoder":{"parent":"sshd","name":"sshd"},'
    b'"data":{"srcip":"198.51.100.7","srcuser":"postgres"},'
    b'"location":"/var/log/auth.log"}'
)


class TestWazuhPushSource:
    def test_identity_properties(self) -> None:
        source = WazuhPushSource()
        assert source.source_type == "wazuh"
        assert source.source_version == "1.0.0"
        assert source.delivery_mode == IntegrationDeliveryMode.PUSH

    @pytest.mark.asyncio
    async def test_real_captured_alert_is_accepted_as_one_event(self) -> None:
        source = WazuhPushSource()

        result = await source.parse_push_event(_REAL_CAPTURED_ALERT)

        assert result == [_REAL_CAPTURED_ALERT]

    @pytest.mark.asyncio
    async def test_minimal_valid_alert_shape_is_accepted(self) -> None:
        source = WazuhPushSource()
        body = json.dumps(
            {"timestamp": "2026-08-09T00:00:00.000+0000", "rule": {"level": 3, "id": "502"}}
        ).encode()

        result = await source.parse_push_event(body)

        assert result == [body]

    @pytest.mark.asyncio
    async def test_non_json_body_raises_parsing_error(self) -> None:
        source = WazuhPushSource()

        with pytest.raises(ParsingError):
            await source.parse_push_event(b"not json at all")

    @pytest.mark.asyncio
    async def test_json_array_raises_parsing_error(self) -> None:
        source = WazuhPushSource()
        body = json.dumps([{"rule": {}, "timestamp": "x"}]).encode()

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)

    @pytest.mark.asyncio
    async def test_missing_rule_field_raises_parsing_error(self) -> None:
        source = WazuhPushSource()
        body = json.dumps({"timestamp": "2026-08-09T00:00:00.000+0000"}).encode()

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)

    @pytest.mark.asyncio
    async def test_missing_timestamp_field_raises_parsing_error(self) -> None:
        source = WazuhPushSource()
        body = json.dumps({"rule": {"level": 5, "id": "5710"}}).encode()

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)

    @pytest.mark.asyncio
    async def test_generic_webhook_batch_envelope_is_not_unwrapped(self) -> None:
        """WazuhPushSource must NOT special-case a {"events": [...]} envelope
        -- Wazuh's real wire shape has no such thing, so a real alert whose
        own body happens to contain an "events" key (unlikely but possible
        in a nested `data` sub-object) must not be misinterpreted as a
        generic-webhook-style batch."""
        source = WazuhPushSource()
        body = json.dumps(
            {
                "timestamp": "2026-08-09T00:00:00.000+0000",
                "rule": {"level": 5, "id": "1"},
                "events": [{"id": 1}, {"id": 2}],
            }
        ).encode()

        result = await source.parse_push_event(body)

        assert result == [body]
