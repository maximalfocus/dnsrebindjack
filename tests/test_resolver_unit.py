"""Unit tests for the resolver's flip logic, with no DNS server or network involved."""

from __future__ import annotations

from dnsrebindjack.fixtures import data
from dnsrebindjack.fixtures.resolver import ResolverState, attacker_answer


def test_attacker_answer_flips_after_the_first_query() -> None:
    assert attacker_answer(0) == data.ALLOWED_FIRST_IP
    assert attacker_answer(1) == data.INTERNAL_IP
    assert attacker_answer(2) == data.INTERNAL_IP  # stays internal thereafter


def test_state_flips_attacker_name_only_on_a_queries() -> None:
    state = ResolverState()
    # An AAAA query must not consume the flip.
    assert state.answer_for(data.ATTACKER_NAME, is_a_query=False) is None
    assert state.answer_for(data.ATTACKER_NAME, is_a_query=True) == data.ALLOWED_FIRST_IP
    assert state.answer_for(data.ATTACKER_NAME, is_a_query=True) == data.INTERNAL_IP


def test_state_is_stable_for_legit_name() -> None:
    state = ResolverState()
    assert state.answer_for(data.LEGIT_NAME, is_a_query=True) == data.UPSTREAM_IP
    assert state.answer_for(data.LEGIT_NAME, is_a_query=True) == data.UPSTREAM_IP
    assert state.answer_for(data.LEGIT_NAME, is_a_query=False) is None


def test_state_does_not_serve_unknown_names() -> None:
    state = ResolverState()
    assert not state.is_known("example.com")
    assert state.answer_for("example.com", is_a_query=True) is None
    assert state.is_known(data.ATTACKER_NAME.upper() + ".")  # case/trailing-dot tolerant


def test_reset_returns_to_the_first_allowed_answer() -> None:
    state = ResolverState()
    assert state.answer_for(data.ATTACKER_NAME, is_a_query=True) == data.ALLOWED_FIRST_IP
    assert state.answer_for(data.ATTACKER_NAME, is_a_query=True) == data.INTERNAL_IP
    state.reset()
    assert state.answer_for(data.ATTACKER_NAME, is_a_query=True) == data.ALLOWED_FIRST_IP


def test_record_and_log_are_observable() -> None:
    state = ResolverState()
    state.record(name=data.ATTACKER_NAME, qtype="A", answer=data.ALLOWED_FIRST_IP)
    state.record(name=data.LEGIT_NAME, qtype="A", answer=data.UPSTREAM_IP)
    log = state.log()
    assert [entry["answer"] for entry in log] == [data.ALLOWED_FIRST_IP, data.UPSTREAM_IP]
    assert log[0]["name"] == data.ATTACKER_NAME
    state.reset()
    assert state.log() == []
