"""Exercises examples/fastapi_app.py against a real TestClient - the FastAPI
example in docs/integration.md is not just eyeballed, it's this test."""

from __future__ import annotations

import sys
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from fastapi_app import SESSION_COOKIE, create_app  # noqa: E402


@pytest.fixture
def client(auth):
    auth.create_user("you@example.com", "correct horse battery staple")
    return TestClient(create_app(auth))


def test_login_sets_a_cookie_and_me_reports_the_account(client):
    r = client.post(
        "/auth/login",
        json={"email": "you@example.com", "password": "correct horse battery staple"},
    )
    assert r.status_code == 200
    assert r.json() == {"email": "you@example.com"}
    assert SESSION_COOKIE in client.cookies

    r = client.get("/auth/me")
    assert r.status_code == 200
    assert r.json() == {"email": "you@example.com", "totp_enabled": False}


def test_wrong_password_is_401(client):
    r = client.post("/auth/login", json={"email": "you@example.com", "password": "wrong"})
    assert r.status_code == 401


def test_me_without_a_session_is_401(client):
    assert client.get("/auth/me").status_code == 401


def test_logout_then_me_is_401(client):
    client.post(
        "/auth/login",
        json={"email": "you@example.com", "password": "correct horse battery staple"},
    )
    r = client.post("/auth/logout")
    assert r.status_code == 204

    assert client.get("/auth/me").status_code == 401


def test_2fa_confirm_with_a_bad_code_is_422_not_401(client):
    # enrolment failures use the general map (422); only a bad code AT LOGIN
    # is 401 - this is the split the whole example exists to demonstrate
    client.post(
        "/auth/login",
        json={"email": "you@example.com", "password": "correct horse battery staple"},
    )
    r = client.post("/auth/2fa/setup")
    assert r.status_code == 200

    r = client.post("/auth/2fa/confirm", json={"otp": "000000"})
    assert r.status_code == 422


def test_full_2fa_round_trip(client, clock):
    client.post(
        "/auth/login",
        json={"email": "you@example.com", "password": "correct horse battery staple"},
    )
    secret = client.post("/auth/2fa/setup").json()["secret"]
    code = pyotp.TOTP(secret).at(clock())
    r = client.post("/auth/2fa/confirm", json={"otp": code})
    assert r.status_code == 200
    assert len(r.json()["recovery_codes"]) == 10

    # a fresh login now needs the code - and a bad one there is 401, not 422
    client.cookies.clear()
    r = client.post(
        "/auth/login",
        json={"email": "you@example.com", "password": "correct horse battery staple"},
    )
    assert r.status_code == 401 and r.json()["otp_required"] is True

    r = client.post(
        "/auth/login",
        json={
            "email": "you@example.com",
            "password": "correct horse battery staple",
            "otp": "000000",
        },
    )
    assert r.status_code == 401  # OtpInvalid, but AT LOGIN -> 401

    r = client.post(
        "/auth/login",
        json={
            "email": "you@example.com",
            "password": "correct horse battery staple",
            "otp": pyotp.TOTP(secret).at(clock()),
        },
    )
    assert r.status_code == 200
