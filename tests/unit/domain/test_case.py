"""Unit tests for Case domain model."""

from __future__ import annotations

import uuid

from src.domain.case import CaseStatus
from tests.fixtures.factories import make_case


class TestCase:
    def test_initial_status_open(self) -> None:
        case = make_case()
        assert case.status == CaseStatus.OPEN

    def test_with_status(self) -> None:
        case = make_case()
        closed = case.with_status(CaseStatus.CLOSED)
        assert closed.status == CaseStatus.CLOSED
        assert case.status == CaseStatus.OPEN  # original immutable

    def test_with_member(self) -> None:
        case = make_case()
        member_id = uuid.uuid4()
        case2 = case.with_member(member_id)
        assert member_id in case2.member_user_ids
        assert member_id not in case.member_user_ids

    def test_without_member(self) -> None:
        case = make_case()
        member_id = uuid.uuid4()
        with_member = case.with_member(member_id)
        without_member = with_member.without_member(member_id)
        assert member_id not in without_member.member_user_ids
        assert member_id in with_member.member_user_ids  # original immutable

    def test_without_member_idempotent_for_non_member(self) -> None:
        case = make_case()
        stranger_id = uuid.uuid4()
        result = case.without_member(stranger_id)
        assert stranger_id not in result.member_user_ids

    def test_case_id_auto_generated(self) -> None:
        case = make_case()
        assert isinstance(case.case_id, uuid.UUID)

    def test_metadata_title_required(self) -> None:
        case = make_case()
        assert case.metadata.title == "Test Case"
