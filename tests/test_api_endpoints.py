"""Tests for the HTTP/REST/OpenAPI endpoint detector.

Proves that paths + methods are extracted from an OpenAPI spec and from
FastAPI / Express route definitions, that the BOLA-candidate risk indicator
fires on id-bearing paths, and that evidence.metadata carries the documented
CATEGORY_API contract keys.
"""
from __future__ import annotations

from pathlib import Path

from ai_surface.detectors.api_endpoints import ApiEndpointDetector
from ai_surface.types import CATEGORY_API, Finding

FIXTURES = Path(__file__).parent / "fixtures" / "api_endpoints"

_API_METADATA_KEYS = {"method", "path", "source_spec", "auth", "framework"}
_BOLA = "object-id in path (BOLA candidate)"


def _by_mp(findings: list[Finding]) -> dict[tuple[str, str], Finding]:
    """Index findings by (method, path)."""
    return {(f.evidence.metadata["method"], f.evidence.metadata["path"]): f for f in findings}


def _assert_contract(f: Finding) -> None:
    assert f.category == CATEGORY_API
    # Discovery only: no severity, no audit, no bridges.
    assert f.severity is None
    assert f.audit is None
    assert f.bridges == []
    # All five documented metadata keys are always present.
    assert _API_METADATA_KEYS <= set(f.evidence.metadata.keys())
    # Snippet capped.
    assert len(f.evidence.snippet) <= 200


# ---------------------------------------------------------------------------
# OpenAPI spec
# ---------------------------------------------------------------------------


def test_openapi_spec_paths_and_methods() -> None:
    findings = ApiEndpointDetector().detect(str(FIXTURES / "spec"))
    by_mp = _by_mp(findings)

    # Every path+method pair in the spec is emitted.
    assert ("GET", "/v1/orders") in by_mp
    assert ("POST", "/v1/orders") in by_mp
    assert ("POST", "/v1/orders/{id}/refund") in by_mp
    assert ("GET", "/healthz") in by_mp
    assert len(findings) == 4

    for f in findings:
        _assert_contract(f)
        # source_spec points at the spec file; framework is empty for specs.
        assert f.evidence.metadata["source_spec"].endswith("openapi.yaml")
        assert f.evidence.metadata["framework"] == ""


def test_openapi_surface_and_auth_derived() -> None:
    findings = ApiEndpointDetector().detect(str(FIXTURES / "spec"))
    refund = _by_mp(findings)[("POST", "/v1/orders/{id}/refund")]

    assert refund.surface == "REST API: POST /v1/orders/{id}/refund"
    # Auth derived from the bearer securityScheme.
    assert refund.evidence.metadata["auth"] == "bearer"


def test_openapi_bola_candidate_indicator_fires_on_id_path() -> None:
    findings = ApiEndpointDetector().detect(str(FIXTURES / "spec"))
    by_mp = _by_mp(findings)

    # {id} segment -> BOLA candidate.
    assert _BOLA in by_mp[("POST", "/v1/orders/{id}/refund")].risk_indicators
    # No id segment -> no BOLA indicator.
    assert _BOLA not in by_mp[("GET", "/v1/orders")].risk_indicators
    assert by_mp[("GET", "/healthz")].risk_indicators == []


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------


def test_fastapi_routes_extracted() -> None:
    findings = ApiEndpointDetector().detect(str(FIXTURES / "fastapi"))
    by_mp = _by_mp(findings)

    assert ("GET", "/v1/users") in by_mp
    assert ("POST", "/v1/users") in by_mp
    assert ("DELETE", "/v1/users/{user_id}") in by_mp
    assert ("PATCH", "/v1/users/{user_id}/role") in by_mp

    for f in findings:
        _assert_contract(f)
        assert f.evidence.metadata["framework"] == "fastapi"
        assert f.evidence.metadata["auth"] == "unknown"
        assert f.evidence.metadata["source_spec"] == ""


def test_fastapi_bola_candidate_on_user_id() -> None:
    findings = ApiEndpointDetector().detect(str(FIXTURES / "fastapi"))
    by_mp = _by_mp(findings)

    # {user_id} is an id-like segment.
    assert _BOLA in by_mp[("DELETE", "/v1/users/{user_id}")].risk_indicators
    assert _BOLA not in by_mp[("GET", "/v1/users")].risk_indicators


# ---------------------------------------------------------------------------
# Express
# ---------------------------------------------------------------------------


def test_express_routes_extracted() -> None:
    findings = ApiEndpointDetector().detect(str(FIXTURES / "express"))
    by_mp = _by_mp(findings)

    assert ("GET", "/api/products") in by_mp
    assert ("POST", "/api/products") in by_mp
    assert ("GET", "/api/products/:id") in by_mp
    assert ("DELETE", "/api/products/:id") in by_mp

    for f in findings:
        _assert_contract(f)
        assert f.evidence.metadata["framework"] == "express"


def test_express_bola_candidate_on_colon_id() -> None:
    findings = ApiEndpointDetector().detect(str(FIXTURES / "express"))
    by_mp = _by_mp(findings)

    # :id is an id-like segment.
    assert _BOLA in by_mp[("GET", "/api/products/:id")].risk_indicators
    assert _BOLA not in by_mp[("GET", "/api/products")].risk_indicators


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_empty_dir_returns_empty(tmp_path: Path) -> None:
    assert ApiEndpointDetector().detect(str(tmp_path)) == []


def test_nonexistent_path_returns_empty() -> None:
    assert ApiEndpointDetector().detect("/no/such/path/exists/here") == []


def test_detector_identity() -> None:
    det = ApiEndpointDetector()
    assert det.name == "api_endpoints"
    assert det.category == CATEGORY_API
