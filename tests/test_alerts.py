"""Alert delivery: the webhook target is untrusted configuration."""

from __future__ import annotations

import pytest

from sentinel.alerts import _send_slack, _send_webhook


def test_webhook_refuses_non_http_schemes() -> None:
    """A config-supplied webhook must not be able to read local files.

    ``urllib.request.urlopen`` honours whatever handler the scheme names, so an
    unvalidated ``file://`` target turns the alerting path into a local-file
    reader. The webhook is operator configuration, so the scheme is checked
    before anything is fetched.
    """
    for url in (
        "file:///etc/passwd",
        "ftp://example.invalid/hook",
        "gopher://example.invalid/hook",
        "/etc/passwd",
        "",
    ):
        assert _send_webhook(url, {"text": "x"}) is False, url


def test_webhook_accepts_http_and_https(monkeypatch: pytest.MonkeyPatch) -> None:
    """The two real schemes still reach the transport, so alerts are not dead."""
    seen: list[str] = []

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(req, timeout=None):  # noqa: ANN001, ANN202 - urlopen signature
        seen.append(req.full_url)
        return _Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    for url in ("http://example.invalid/hook", "https://example.invalid/hook"):
        assert _send_webhook(url, {"text": "x"}) is True, url
    assert seen == ["http://example.invalid/hook", "https://example.invalid/hook"]


def test_slack_delivery_inherits_the_scheme_check() -> None:
    """_send_slack delegates to _send_webhook, so it inherits the guard."""
    assert _send_slack("file:///etc/passwd", {"text": "x"}) is False
