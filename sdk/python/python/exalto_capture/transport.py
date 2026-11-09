"""``httpx`` transports that capture every request they send.

Pass one to the ``http_client`` of an OpenAI or Anthropic client and use the
client as usual::

    import httpx
    from anthropic import Anthropic
    from exalto_capture import Client, Notary
    from exalto_capture.transport import CaptureTransport

    def keep(artifact):
        bucket.put_object(Key=f"{artifact.trace_id}.{artifact.extension}", Body=artifact.data)

    client = Client(Notary.exalto(api_key=EXALTO_API_KEY))
    http = httpx.Client(transport=CaptureTransport(client, mode="witnessed", on_artifact=keep))
    anthropic = Anthropic(http_client=http)

``on_artifact`` receives each ``Artifact`` once its response body has been
read to the end. A provider error response is passed through but never
sealed. A response whose body is never read produces no artifact.

The provider has already answered by the time an artifact is ready, so a
failure to produce or keep one never fails the model call, which a client
would otherwise retry as a new, paid request. It goes to ``on_error``, which
logs it by default.

The client's read timeout bounds the wait for the response headers and for
each body chunk; when it passes, the transport raises ``httpx.ReadTimeout``.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, AsyncIterator, Awaitable, Callable, Iterator, Literal, Optional, Union

import anyio
import httpx

from ._native import Artifact, CaptureKey, CaptureTimeout, Client, Response

Mode = Literal["witnessed", "notarized"]

__all__ = ["AsyncCaptureTransport", "CaptureTransport", "Mode"]

_log = logging.getLogger("exalto_capture")

# Each in-flight call holds a worker thread while the native side waits. A
# limiter of its own keeps those calls from exhausting the thread pool that
# the rest of an async application shares.
_ASYNC_CALLS = 256


def _log_error(error: Exception) -> None:
    _log.error("Exalto Capture produced no artifact for a provider response: %s", error)


def _checked(mode: str, key: Optional[CaptureKey]) -> None:
    if mode == "witnessed":
        if key is not None:
            raise ValueError("Witnessed capture produces a Sealed trace and takes no key")
    elif mode == "notarized":
        if key is None:
            raise ValueError("Notarized capture needs the CaptureKey that encrypts its .llmcapture")
    else:
        raise ValueError('mode must be "witnessed" or "notarized"')


def _read_timeout(request: httpx.Request) -> Optional[float]:
    return request.extensions.get("timeout", {}).get("read")


def _send(
    client: Client,
    mode: str,
    key: Optional[CaptureKey],
    request: httpx.Request,
    body: bytes,
    timeout: Optional[float],
) -> Response:
    headers = list(request.headers.raw)
    try:
        if mode == "witnessed":
            return client.witness(request.method, str(request.url), headers, body, timeout)
        return client.capture(request.method, str(request.url), headers, body, key, timeout)
    except CaptureTimeout as error:
        raise httpx.ReadTimeout(str(error), request=request) from error


def _next_chunk(response: Response, request: httpx.Request, timeout: Optional[float]) -> Optional[bytes]:
    try:
        return response.next_chunk(timeout)
    except CaptureTimeout as error:
        raise httpx.ReadTimeout(str(error), request=request) from error


def _sealable(response: Response) -> bool:
    return 200 <= response.status < 300


class _Stream(httpx.SyncByteStream):
    def __init__(
        self,
        response: Response,
        request: httpx.Request,
        timeout: Optional[float],
        on_artifact: Callable[[Artifact], Any],
        on_error: Callable[[Exception], Any],
    ) -> None:
        self._response = response
        self._request = request
        self._timeout = timeout
        self._on_artifact = on_artifact
        self._on_error = on_error

    def __iter__(self) -> Iterator[bytes]:
        while (chunk := _next_chunk(self._response, self._request, self._timeout)) is not None:
            yield chunk
        if _sealable(self._response):
            try:
                self._on_artifact(self._response.artifact())
            except Exception as error:
                self._on_error(error)

    def close(self) -> None:
        self._response.close()


class _AsyncStream(httpx.AsyncByteStream):
    def __init__(
        self,
        response: Response,
        request: httpx.Request,
        timeout: Optional[float],
        on_artifact: Callable[[Artifact], Union[Any, Awaitable[Any]]],
        on_error: Callable[[Exception], Union[Any, Awaitable[Any]]],
        limiter: anyio.CapacityLimiter,
    ) -> None:
        self._response = response
        self._request = request
        self._timeout = timeout
        self._on_artifact = on_artifact
        self._on_error = on_error
        self._limiter = limiter

    async def _run(self, function: Callable[[], Any]) -> Any:
        return await anyio.to_thread.run_sync(function, abandon_on_cancel=True, limiter=self._limiter)

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while (
            chunk := await self._run(lambda: _next_chunk(self._response, self._request, self._timeout))
        ) is not None:
            yield chunk
        if _sealable(self._response):
            try:
                result = self._on_artifact(await self._run(self._response.artifact))
                if inspect.isawaitable(result):
                    await result
            except Exception as error:
                result = self._on_error(error)
                if inspect.isawaitable(result):
                    await result

    async def aclose(self) -> None:
        await self._run(self._response.close)


class CaptureTransport(httpx.BaseTransport):
    """Sends every request through ``client`` in ``mode``.

    ``"witnessed"`` hands ``on_artifact`` a Sealed ``.llmtrace``;
    ``"notarized"`` hands it a ``.llmcapture`` encrypted under ``key``.
    """

    def __init__(
        self,
        client: Client,
        *,
        mode: Mode,
        on_artifact: Callable[[Artifact], Any],
        key: Optional[CaptureKey] = None,
        on_error: Callable[[Exception], Any] = _log_error,
    ) -> None:
        _checked(mode, key)
        self._client = client
        self._mode = mode
        self._key = key
        self._on_artifact = on_artifact
        self._on_error = on_error

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        timeout = _read_timeout(request)
        response = _send(self._client, self._mode, self._key, request, request.read(), timeout)
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_Stream(response, request, timeout, self._on_artifact, self._on_error),
        )


class AsyncCaptureTransport(httpx.AsyncBaseTransport):
    """The async counterpart of ``CaptureTransport``. ``on_artifact`` and
    ``on_error`` may be coroutine functions."""

    def __init__(
        self,
        client: Client,
        *,
        mode: Mode,
        on_artifact: Callable[[Artifact], Union[Any, Awaitable[Any]]],
        key: Optional[CaptureKey] = None,
        on_error: Callable[[Exception], Union[Any, Awaitable[Any]]] = _log_error,
    ) -> None:
        _checked(mode, key)
        self._client = client
        self._mode = mode
        self._key = key
        self._on_artifact = on_artifact
        self._on_error = on_error
        self._limiter: Optional[anyio.CapacityLimiter] = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._limiter is None:
            self._limiter = anyio.CapacityLimiter(_ASYNC_CALLS)
        body = await request.aread()
        timeout = _read_timeout(request)
        response = await anyio.to_thread.run_sync(
            lambda: _send(self._client, self._mode, self._key, request, body, timeout),
            abandon_on_cancel=True,
            limiter=self._limiter,
        )
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_AsyncStream(
                response, request, timeout, self._on_artifact, self._on_error, self._limiter
            ),
        )
