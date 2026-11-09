"""Seal model-provider calls with an Exalto Capture notary.

Every call returns the provider's response plus its evidence as bytes. Store
those bytes wherever you like.

- Witnessed (``Client.witness``): the notary relays the request, credential
  included, and signs a receipt. The artifact is a Sealed ``.llmtrace``. It is
  trust in the notary operator, not a cryptographic proof.
- Notarized (``Client.capture``): Proxy-TLS. The notary never receives
  plaintext or the credential. The artifact is a ``.llmcapture`` encrypted
  under your ``CaptureKey``; it can rebuild the original request, credential
  included, so store it as a secret. Seal it whenever you need to prove it
  with ``Client.notarize``.

``verify`` and ``Notary.verify`` check a ``.llmtrace`` offline.
"""

from ._native import (
    EXALTO_API_ORIGIN,
    Artifact,
    CaptureError,
    CaptureKey,
    CaptureTimeout,
    Client,
    Notary,
    Response,
    Verification,
    verify,
)

__all__ = [
    "EXALTO_API_ORIGIN",
    "Artifact",
    "CaptureError",
    "CaptureKey",
    "CaptureTimeout",
    "Client",
    "Notary",
    "Response",
    "Verification",
    "verify",
]
