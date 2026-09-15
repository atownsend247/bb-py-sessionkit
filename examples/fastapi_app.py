"""A complete FastAPI integration: cookie session, 2FA, error mapping.

This is the canonical source for the example in docs/integration.md - the
markdown embeds this file's contents verbatim, and
tests/test_docs_examples_in_sync.py fails CI if the two ever drift apart.
tests/test_example_fastapi.py runs it against a real TestClient, so this
example is exercised by the normal test suite, not just eyeballed.

Edit this file, not the code fence in the docs - see
docs/development.md#keeping-the-example-honest.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from sessionkit import (
    AuthenticationError,
    AuthError,
    AuthService,
    DuplicateUser,
    OtpInvalid,
    OtpLocked,
    OtpRequired,
    SqliteAuthStore,
    UserNotFound,
    ValidationError,
)

SESSION_COOKIE = "session_token"

# One place maps every AuthError subclass to a status code. Order doesn't
# matter here (each key is checked with isinstance, first match wins) as long
# as OtpInvalid has its own entry - it's the one AuthError subclass that is
# NOT an AuthenticationError, so it won't be caught by that entry.
_ERROR_STATUS: dict[type[AuthError], int] = {
    AuthenticationError: 401,   # covers OtpRequired / OtpLocked too
    OtpInvalid: 422,            # not an AuthenticationError subclass - map it explicitly
    UserNotFound: 404,
    DuplicateUser: 409,
    ValidationError: 422,
}


def create_app(auth: AuthService) -> FastAPI:
    app = FastAPI()

    async def _handle_auth_error(_request: Request, exc: AuthError) -> JSONResponse:
        status = next((s for t, s in _ERROR_STATUS.items() if isinstance(exc, t)), 400)
        return JSONResponse(status_code=status, content={"detail": str(exc)})

    for exc_type in _ERROR_STATUS:
        app.add_exception_handler(exc_type, _handle_auth_error)

    def current_user(request: Request):
        # AuthenticationError propagates to the handler above -> 401
        return auth.user_for_token(request.cookies.get(SESSION_COOKIE))

    @app.post("/auth/login")
    def login(payload: dict, response: Response):
        try:
            result = auth.login(payload["email"], payload["password"], otp=payload.get("otp"))
        except OtpRequired as exc:
            return JSONResponse(status_code=401, content={"detail": str(exc), "otp_required": True})
        except OtpLocked as exc:
            return JSONResponse(status_code=401, content={"detail": str(exc), "otp_locked": True})
        except OtpInvalid as exc:
            # a bad 2FA code AT LOGIN is an authentication failure (401) -
            # the general map above gives OtpInvalid 422 everywhere else
            # (e.g. /auth/2fa/confirm below), which is the right status there
            return JSONResponse(status_code=401, content={"detail": str(exc)})
        response.set_cookie(SESSION_COOKIE, result.token, httponly=True, samesite="lax")
        return {"email": result.user.email}

    @app.post("/auth/logout", status_code=204)
    def logout(request: Request, response: Response):
        auth.logout(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE)

    @app.get("/auth/me")
    def me(user=Depends(current_user)):
        return {"email": user.email, "totp_enabled": user.totp_enabled}

    @app.post("/auth/2fa/setup")
    def setup_2fa(user=Depends(current_user)):
        enrol = auth.start_totp_enrollment(user.id)
        return {"secret": enrol.secret, "otpauth_uri": enrol.uri}

    @app.post("/auth/2fa/confirm")
    def confirm_2fa(payload: dict, user=Depends(current_user)):
        # a wrong code here hits the general map -> 422 (OtpInvalid, not
        # AuthenticationError) - this is enrolment, not a login attempt
        codes = auth.confirm_totp(user.id, payload["otp"])
        return {"recovery_codes": codes}

    return app
