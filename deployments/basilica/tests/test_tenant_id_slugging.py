"""Tests for the permissive `validate_tenant_id` and the `_basilica_slug`
derivation (issue #259).

The caller passes any human-readable identifier (UUID, email, opaque
string). The library accepts it as-is and derives a deterministic
DNS-safe slug internally for Basilica deployment naming. The slug logic
itself is exercised directly here — no mocks, no stubs.
"""

from __future__ import annotations

import re

import pytest

from deployments.basilica import lifecycle


_SLUG_REGEX = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")


# ---------------------------------------------------------------------------
# validate_tenant_id: permissive acceptance + explicit rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tenant_id",
    [
        "acme",
        "ACME",
        "User-With-Caps",
        "550e8400-e29b-41d4-a716-446655440000",
        "alice@acme.example",
        "user_id:42",
        "a" * 256,
        "中文",  # unicode is fine; only whitespace / control are rejected
    ],
)
def test_validate_tenant_id_accepts_arbitrary_identifiers(tenant_id: str) -> None:
    assert lifecycle.validate_tenant_id(tenant_id) == tenant_id


@pytest.mark.parametrize(
    "tenant_id",
    [
        "has space",
        "has\ttab",
        "has\nnewline",
        "has\x00null",
        "has\x1fctl",
        "has\x7fdel",
    ],
)
def test_validate_tenant_id_rejects_whitespace_and_control(tenant_id: str) -> None:
    with pytest.raises(ValueError, match="whitespace or control"):
        lifecycle.validate_tenant_id(tenant_id)


def test_validate_tenant_id_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        lifecycle.validate_tenant_id("")


def test_validate_tenant_id_rejects_over_max_length() -> None:
    with pytest.raises(ValueError, match="exceeds max"):
        lifecycle.validate_tenant_id("a" * (lifecycle.MAX_TENANT_ID_LEN + 1))


def test_validate_tenant_id_rejects_non_string() -> None:
    with pytest.raises(ValueError, match="must be a str"):
        lifecycle.validate_tenant_id(12345)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _basilica_slug: DNS-safe + deterministic + collision-resistant
# ---------------------------------------------------------------------------


def test_slug_is_dns_safe_for_short_input() -> None:
    slug = lifecycle._basilica_slug("acme")
    assert _SLUG_REGEX.match(slug), slug
    assert slug.startswith("acme-")


def test_slug_for_256_char_input_is_within_30_chars_and_valid() -> None:
    long_id = "a" * 256
    slug = lifecycle._basilica_slug(long_id)
    assert len(slug) <= 30
    assert _SLUG_REGEX.match(slug), slug


def test_slug_for_uuid_is_deterministic_and_dns_safe() -> None:
    uuid_id = "550e8400-e29b-41d4-a716-446655440000"
    lifecycle.validate_tenant_id(uuid_id)
    a = lifecycle._basilica_slug(uuid_id)
    b = lifecycle._basilica_slug(uuid_id)
    assert a == b
    assert _SLUG_REGEX.match(a), a


def test_slug_for_email_is_dns_safe_and_keeps_recognisable_prefix() -> None:
    email_id = "alice@acme.example"
    lifecycle.validate_tenant_id(email_id)
    slug = lifecycle._basilica_slug(email_id)
    assert _SLUG_REGEX.match(slug), slug
    # The local-part-ish prefix survives slugging so an operator can still
    # eyeball the deployment back to its tenant.
    assert slug.startswith("alice-acme-example"[:23])


def test_slug_is_deterministic_across_repeated_calls() -> None:
    tid = "User-With-Caps"
    first = lifecycle._basilica_slug(tid)
    for _ in range(5):
        assert lifecycle._basilica_slug(tid) == first


def test_two_inputs_sharing_prefix_get_different_hash_suffix() -> None:
    """`alice@acme.example` and `alice_acme_example` both clean to a
    prefix starting with `alice-acme-example`; the 6-char hash suffix
    must distinguish them.
    """
    a = lifecycle._basilica_slug("alice@acme.example")
    b = lifecycle._basilica_slug("alice_acme_example")
    assert a != b
    assert a.rsplit("-", 1)[0] == b.rsplit("-", 1)[0], (
        "expected the sanitised prefixes to match"
    )
    assert a.rsplit("-", 1)[1] != b.rsplit("-", 1)[1], (
        "expected different hash suffixes"
    )


def test_slug_falls_back_to_tenant_prefix_when_sanitisation_yields_empty() -> None:
    # All chars are stripped — the helper must still produce a valid slug.
    slug = lifecycle._basilica_slug("@@@")
    assert slug.startswith("tenant-")
    assert _SLUG_REGEX.match(slug), slug


def test_slug_collision_suffix_differs_for_different_inputs() -> None:
    # Different inputs that sanitise to identical prefixes must still
    # produce different final slugs.
    inputs = ["acme", "ACME", "a c m e", "@acme@"]
    # Filter out invalid (whitespace) for the slug call — `_basilica_slug`
    # accepts anything but `validate_tenant_id` would reject the
    # space-containing one. For pure slug collision-resistance we feed
    # the helper directly.
    slugs = {lifecycle._basilica_slug(inp) for inp in inputs}
    assert len(slugs) == len(inputs), f"slug collision: {slugs}"
