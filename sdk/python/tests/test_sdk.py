"""Offline tests: the native module's local behavior and the httpx2 transports."""

import asyncio
import importlib.util
import json
import unittest

import httpx2

import exalto_capture
from exalto_capture import (
    CaptureError,
    CaptureKey,
    CaptureTimeout,
    Client,
    NotCapturable,
    Notary,
    Unavailable,
)
from exalto_capture.transport import AsyncCaptureTransport, CaptureTransport

# The public key of secp256k1 secret key 1, a valid SEC1 point.
NOTARY_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


class NativeTest(unittest.TestCase):
    def test_capture_keys_round_trip_and_never_print(self):
        key = CaptureKey.generate()
        self.assertEqual(len(key.to_bytes()), 32)
        self.assertEqual(CaptureKey.from_bytes(key.to_bytes()).to_bytes(), key.to_bytes())
        self.assertEqual(repr(key), "CaptureKey(<redacted>)")
        with self.assertRaises(CaptureError):
            CaptureKey.from_bytes(b"short")

    def test_notary_configuration_is_validated(self):
        Notary("tls://notary.example:443", NOTARY_KEY)
        with self.assertRaises(CaptureError):
            Notary("https://notary.example", NOTARY_KEY)
        with self.assertRaises(CaptureError):
            Notary("tls://notary.example:443", "not-a-key")

    def test_only_post_to_a_fixed_provider_is_sent(self):
        client = Client(Notary("tls://notary.example:443", NOTARY_KEY))
        for method, url in [
            ("GET", "https://api.openai.com/v1/models"),
            ("POST", "https://example.com/v1/responses"),
        ]:
            with self.assertRaises(NotCapturable):
                client.witness(method, url, [], b"{}")

    def test_a_notary_that_cannot_be_reached_is_unavailable(self):
        # Nothing listens on port 1 of the loopback address.
        client = Client(Notary("tcp://127.0.0.1:1", NOTARY_KEY))
        with self.assertRaises(Unavailable) as raised:
            client.witness("POST", "https://api.openai.com/v1/responses", [], b"{}")
        self.assertIsInstance(raised.exception, CaptureError)

    def test_verify_rejects_bytes_that_are_not_a_trace(self):
        with self.assertRaises(CaptureError):
            exalto_capture.verify(b"not a trace", NOTARY_KEY)


class FakeResponse:
    def __init__(self, status, chunks, artifact="artifact", content_type=b"text/event-stream"):
        self.status = status
        self.trace_id = "trc-1"
        self.headers = [(b"content-type", content_type)]
        self._chunks = list(chunks)
        self._artifact = artifact
        self.artifacts_taken = 0
        self.closed = False
        self.timeouts = []

    def next_chunk(self, timeout=None):
        self.timeouts.append(timeout)
        if self._chunks and self._chunks[0] is TIMEOUT:
            raise CaptureTimeout("too slow")
        return self._chunks.pop(0) if self._chunks else None

    def artifact(self):
        self.artifacts_taken += 1
        if isinstance(self._artifact, Exception):
            raise self._artifact
        return self._artifact

    def close(self):
        self.closed = True


TIMEOUT = object()


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.sent = None

    def witness(self, method, url, headers, body, timeout=None):
        self.sent = ("witness", method, url, dict(headers), body)
        return self.response

    def capture(self, method, url, headers, body, key, timeout=None):
        self.sent = ("capture", method, url, dict(headers), body, key)
        return self.response


class TransportTest(unittest.TestCase):
    def test_streams_the_body_then_hands_over_the_artifact(self):
        fake = FakeClient(FakeResponse(200, [b"data: 1\n\n", b"data: 2\n\n"]))
        artifacts = []
        transport = CaptureTransport(fake, mode="witnessed", on_artifact=artifacts.append)
        with httpx2.Client(transport=transport) as http:
            response = http.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": "secret"},
                content=b'{"stream":true}',
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"data: 1\n\ndata: 2\n\n")
        self.assertEqual(artifacts, ["artifact"])
        kind, method, url, headers, body = fake.sent
        self.assertEqual((kind, method, url, body), ("witness", "POST", "https://api.anthropic.com/v1/messages", b'{"stream":true}'))
        self.assertEqual(headers[b"x-api-key"], b"secret")

    def test_a_provider_error_passes_through_unsealed(self):
        fake = FakeClient(FakeResponse(429, [b'{"error":"rate"}']))
        artifacts = []
        transport = CaptureTransport(fake, mode="witnessed", on_artifact=artifacts.append)
        with httpx2.Client(transport=transport) as http:
            response = http.post("https://api.openai.com/v1/responses", content=b"{}")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(artifacts, [])
        self.assertEqual(fake.response.artifacts_taken, 0)

    def test_notarized_needs_a_key_and_witnessed_takes_none(self):
        fake = FakeClient(FakeResponse(200, []))
        with self.assertRaises(ValueError):
            CaptureTransport(fake, mode="notarized", on_artifact=print)
        with self.assertRaises(ValueError):
            CaptureTransport(fake, mode="witnessed", on_artifact=print, key=CaptureKey.generate())
        key = CaptureKey.generate()
        transport = CaptureTransport(fake, mode="notarized", on_artifact=lambda _: None, key=key)
        with httpx2.Client(transport=transport) as http:
            http.post("https://api.openai.com/v1/responses", content=b"{}")
        self.assertEqual(fake.sent[0], "capture")
        self.assertIs(fake.sent[5], key)

    def test_an_artifact_failure_never_fails_the_model_call(self):
        # The provider already answered: raising would make the OpenAI and
        # Anthropic clients send the request again.
        fake = FakeClient(FakeResponse(200, [b"{}"], artifact=CaptureError("no receipt")))
        errors = []
        transport = CaptureTransport(fake, mode="witnessed", on_artifact=print, on_error=errors.append)
        with httpx2.Client(transport=transport) as http:
            response = http.post("https://api.openai.com/v1/responses", content=b"{}")
        self.assertEqual(response.content, b"{}")
        self.assertEqual([str(error) for error in errors], ["no receipt"])

        def fail(_):
            raise OSError("bucket unavailable")

        fake = FakeClient(FakeResponse(200, [b"{}"]))
        errors = []
        transport = CaptureTransport(fake, mode="witnessed", on_artifact=fail, on_error=errors.append)
        with httpx2.Client(transport=transport) as http:
            self.assertEqual(http.post("https://api.openai.com/v1/responses", content=b"{}").status_code, 200)
        self.assertEqual([str(error) for error in errors], ["bucket unavailable"])

    def test_the_read_timeout_bounds_each_wait(self):
        fake = FakeClient(FakeResponse(200, [b"a", TIMEOUT]))
        transport = CaptureTransport(fake, mode="witnessed", on_artifact=print)
        with httpx2.Client(transport=transport, timeout=httpx2.Timeout(5.0, read=7.0)) as http:
            with self.assertRaises(httpx2.ReadTimeout):
                http.post("https://api.openai.com/v1/responses", content=b"{}")
        self.assertEqual(fake.response.timeouts, [7.0, 7.0])

    def test_closing_a_stream_early_releases_the_response(self):
        fake = FakeClient(FakeResponse(200, [b"a", b"b"]))
        artifacts = []
        transport = CaptureTransport(fake, mode="witnessed", on_artifact=artifacts.append)
        with httpx2.Client(transport=transport) as http:
            with http.stream("POST", "https://api.openai.com/v1/responses", content=b"{}") as response:
                next(response.iter_raw())
        self.assertTrue(fake.response.closed)
        self.assertEqual(artifacts, [])

    def test_the_async_transport_awaits_a_coroutine_callback(self):
        fake = FakeClient(FakeResponse(200, [b"a", b"b"]))
        artifacts = []

        async def keep(artifact):
            artifacts.append(artifact)

        async def run():
            transport = AsyncCaptureTransport(fake, mode="witnessed", on_artifact=keep)
            async with httpx2.AsyncClient(transport=transport) as http:
                response = await http.post("https://api.openai.com/v1/responses", content=b"{}")
                return response.content

        self.assertEqual(asyncio.run(run()), b"ab")
        self.assertEqual(artifacts, ["artifact"])



def json_response(body):
    return FakeResponse(200, [json.dumps(body).encode()], content_type=b"application/json")


# The provider clients the SDK docs name. CI installs both; a local run
# without them skips these tests.
@unittest.skipUnless(
    importlib.util.find_spec("anthropic") and importlib.util.find_spec("openai"),
    "needs the anthropic and openai packages",
)
class ProviderClientTest(unittest.TestCase):
    def test_anthropic_sends_through_the_transport(self):
        from anthropic import Anthropic

        fake = FakeClient(
            json_response(
                {
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-test",
                    "content": [{"type": "text", "text": "hello"}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
            )
        )
        artifacts = []
        transport = CaptureTransport(fake, mode="witnessed", on_artifact=artifacts.append)
        anthropic = Anthropic(api_key="test", max_retries=0, http_client=httpx2.Client(transport=transport))
        message = anthropic.messages.create(
            model="claude-test", max_tokens=8, messages=[{"role": "user", "content": "hi"}]
        )
        self.assertEqual(message.content[0].text, "hello")
        self.assertEqual(fake.sent[2], "https://api.anthropic.com/v1/messages")
        self.assertEqual(artifacts, ["artifact"])

    def test_openai_sends_through_the_transport(self):
        from openai import OpenAI

        fake = FakeClient(
            json_response(
                {
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "gpt-test",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "hello"},
                            "finish_reason": "stop",
                        }
                    ],
                }
            )
        )
        artifacts = []
        transport = CaptureTransport(fake, mode="witnessed", on_artifact=artifacts.append)
        openai = OpenAI(api_key="test", max_retries=0, http_client=httpx2.Client(transport=transport))
        completion = openai.chat.completions.create(
            model="gpt-test", messages=[{"role": "user", "content": "hi"}]
        )
        self.assertEqual(completion.choices[0].message.content, "hello")
        self.assertEqual(fake.sent[2], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(artifacts, ["artifact"])


if __name__ == "__main__":
    unittest.main()
