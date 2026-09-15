"""Device-side registration simulation."""

from __future__ import annotations

import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class Device:
    def __init__(self, device_type: str = "temperature sensor", did: str | None = None):
        self.did = did or f"did:iiot:{uuid.uuid4()}"
        self.device_type = device_type
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def register(self, fog_node, psk: str, metadata: dict | None = None):
        """Perform the protected connection and proof-of-possession handshake."""
        fog_node.authenticate(psk)
        challenge = fog_node.create_challenge(self.did)
        signature = self.private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
        details = {"device_type": self.device_type, **(metadata or {})}
        return fog_node.register_device(
            psk, self.did, self.public_key_bytes, details,
            challenge=challenge, signature=signature,
        )