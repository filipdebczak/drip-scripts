from enum import Enum
from nacl.signing import SigningKey
from nacl.encoding import Base16Encoder, Base64Encoder

class SignatureType(Enum):
    ED25519 = 0

def sign(
    key: bytes,
    type: SignatureType,
    message: bytes):
    
    if type != SignatureType.ED25519:
        raise Exception("unsupported signature type")
    
    signingKey = SigningKey(key)
    signature = signingKey.sign(message).signature

    b16 = Base16Encoder.encode(signature).decode()
    b64 = Base64Encoder.encode(signature).decode()

    return (signature, b16, b64)