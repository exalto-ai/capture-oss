from typing import Optional

EXALTO_API_ORIGIN: str

class CaptureError(Exception): ...
class CaptureTimeout(CaptureError): ...

class CaptureKey:
    @staticmethod
    def generate() -> CaptureKey: ...
    @staticmethod
    def from_bytes(key: bytes) -> CaptureKey: ...
    def to_bytes(self) -> bytes: ...

class Verification:
    trace_id: str
    evidence_kind: str
    provider: str
    provider_host: str
    created_at_unix_ms: int
    notary_public_key: str
    request_path: str
    package_sha256: str
    trace_otlp_json: bytes

class Notary:
    def __init__(self, endpoint: str, public_key: str) -> None: ...
    @staticmethod
    def exalto(api_key: Optional[str] = None, api_origin: Optional[str] = None) -> Notary: ...
    def verify(self, trace: bytes) -> Verification: ...

class Artifact:
    trace_id: str
    kind: str
    extension: str
    data: bytes

class Response:
    status: int
    trace_id: str
    headers: list[tuple[bytes, bytes]]
    def next_chunk(self, timeout: Optional[float] = None) -> Optional[bytes]: ...
    def artifact(self) -> Artifact: ...
    def close(self) -> None: ...

class Client:
    def __init__(self, notary: Notary) -> None: ...
    def witness(
        self,
        method: str,
        url: str,
        headers: list[tuple[bytes, bytes]],
        body: bytes,
        timeout: Optional[float] = None,
    ) -> Response: ...
    def capture(
        self,
        method: str,
        url: str,
        headers: list[tuple[bytes, bytes]],
        body: bytes,
        key: CaptureKey,
        timeout: Optional[float] = None,
    ) -> Response: ...
    def notarize(self, capture: bytes, key: CaptureKey) -> bytes: ...

def verify(trace: bytes, notary_public_key: str) -> Verification: ...
