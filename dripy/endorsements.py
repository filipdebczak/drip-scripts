from .utils import hex_str_to_bytes
from .crypto import SignatureType, sign

import typing as t

import struct

class Endorsement:
    def __init__(
        self,
        identity = None,
        evidence = None,
        scope = None,
        signature = None
    ):
        self.identity = {} if identity is None else identity
        self.evidence = [] if evidence is None else evidence
        self.scope = {} if scope is None else scope
        self.signature = {} if signature is None else signature

    def toSignatureData(self, byte_format: str) -> bytes:
        return struct.pack(
            byte_format,
            hex_str_to_bytes(self.identity['hhit']),
            hex_str_to_bytes(''.join(self.evidence)),
            self.scope['vnb'],
            self.scope['vna']
        )

    def toDict(self) -> dict:
        return {
            'identity': self.identity,
            'evidence': self.evidence,
            'scope': self.scope,
            'signature': self.signature
        }

    def toBytes(self, byte_format: str) -> bytes:
        return struct.pack(
            byte_format,
            hex_str_to_bytes(self.identity['hhit']),
            hex_str_to_bytes(''.join(self.evidence)),
            self.scope['vnb'],
            self.scope['vna'],
            hex_str_to_bytes(self.signature['sig_b16'])
        )

    @classmethod
    def fromBytes(cls, endorsement_bytes: bytes):
        raise NotImplementedError


class SelfEndorsement(Endorsement):
    BYTE_FORMAT = '16s32sII64s'
    BYTE_FORMAT_NOT_SIGNED = '16s32sII'

    def __init__(
        self,
        hhit: str,
        host_identity: str,
        vnb: int,
        vna: int,
        signature: t.Optional[t.Dict[str, str]] = None
    ):
        super().__init__(
            identity={'hhit': hhit},
            evidence=[host_identity],
            scope={'vnb': vnb, 'vna': vna},
            signature=signature
        )

    def toSignatureData(self) -> bytes:
        return super().toSignatureData(self.BYTE_FORMAT_NOT_SIGNED)

    def sign(self, key: bytes, signature_type: SignatureType):
        sig, b16, b64 = sign(key, signature_type, self.toSignatureData())
        self.signature = {'sig_b16': b16}

    def toBytes(self) -> bytes:
        return super().toBytes(self.BYTE_FORMAT)

    @classmethod
    def fromBytes(cls, endorsement_bytes: bytes):
        try:
            hhit, host_identity, vnb, vna, signature = struct.unpack(cls.BYTE_FORMAT, endorsement_bytes)
            return SelfEndorsement(
                hhit=hhit.hex(),
                host_identity=host_identity.hex(),
                vnb=vnb,
                vna=vna,
                signature={'sig_b16': signature.hex()}
            )
        except struct.error as e:
            raise Exception('Unable to create a Self Endorsement from bytes, details:', e)


class GenericEndorsement(Endorsement):
    BYTE_FORMAT = '16s32s120sII64s'
    BYTE_FORMAT_NOT_SIGNED = '16s32s120sII'

    def __init__(
        self,
        hhit: str,
        host_identity: str,
        self_endrosement: str | SelfEndorsement,
        vnb: int,
        vna: int,
        signature: t.Optional[t.Dict[str, str]] = None
    ):
        self.hhit = hhit
        self.host_identity = host_identity
        self.self_endorsement = self_endrosement
        self.vnb = vnb
        self.vna = vna
        self.signature = signature

        super().__init__(
            identity={'hhit': hhit, 'hi_b16': host_identity},
            evidence=[self_endrosement],
            scope={'vnb': vnb, 'vna': vna},
            signature=signature
        )

    def toSignatureData(self) -> bytes:
        return struct.pack(
            self.BYTE_FORMAT_NOT_SIGNED,
            hex_str_to_bytes(self.hhit),
            hex_str_to_bytes(self.host_identity),
            hex_str_to_bytes(self.self_endorsement) if isinstance(self.self_endorsement, str) else self.self_endorsement.toBytes(),
            self.vnb,
            self.vna
        )

    def sign(self, key: bytes, signature_type: SignatureType):
        sig, b16, b64 = sign(key, signature_type, self.toSignatureData())
        self.signature = {'sig_b16': b16}

    def toBytes(self) -> bytes:
        return struct.pack(
            self.BYTE_FORMAT,
            hex_str_to_bytes(self.hhit),
            hex_str_to_bytes(self.host_identity),
            hex_str_to_bytes(self.self_endorsement) if isinstance(self.self_endorsement, str) else self.self_endorsement.toBytes(),
            self.vnb,
            self.vna,
            hex_str_to_bytes(self.signature['sig_b16']) if self.signature is not None else ''
        )

    @classmethod
    def fromBytes(cls, endorsement_bytes: bytes):
        try:
            hhit, host_identity, self_endorsement, vnb, vna, signature = struct.unpack(cls.BYTE_FORMAT, endorsement_bytes)
            return GenericEndorsement(
                hhit=hhit.hex(),
                host_identity=host_identity.hex(),
                self_endrosement=self_endorsement.hex(),
                vnb=vnb,
                vna=vna,
                signature={'sig_b16': signature.hex()}
            )
        except struct.error as e:
            raise Exception('Unable to create a Generic Endorsement from bytes, details:', e)


class ConciseEndorsement(Endorsement):
    BYTE_FORMAT = '16s16sII64s'
    BYTE_FORMAT_NOT_SIGNED = '16s16sII'

    def __init__(
        self,
        hhit_1: str,
        hhit_2: str,
        vnb: int,
        vna: int,
        signature: t.Optional[t.Dict[str, str]] = None
    ):
        super().__init__(
            identity={'hhit': hhit_1},
            evidence=[hhit_2],
            scope={'vnb': vnb, 'vna': vna},
            signature=signature
        )

    def toSignatureData(self) -> bytes:
        return super().toSignatureData(self.BYTE_FORMAT_NOT_SIGNED)

    def sign(self, key: bytes, signature_type: SignatureType):
        sig, b16, b64 = sign(key, signature_type, self.toSignatureData())
        self.signature = {'sig_b16': b16}

    def toBytes(self) -> bytes:
        return super().toBytes(self.BYTE_FORMAT)

    @classmethod
    def fromBytes(cls, endorsement_bytes: bytes):
        try:
            hhit, hhit_2, vnb, vna, signature = struct.unpack(cls.BYTE_FORMAT, endorsement_bytes)
            return ConciseEndorsement(
                hhit_1=hhit.hex(),
                hhit_2=hhit_2.hex(),
                vnb=vnb,
                vna=vna,
                signature={'sig_b16': signature.hex()}
            )
        except struct.error as e:
            raise Exception('Unable to create a Concise Endorsement from bytes, details:', e)


class MutualEndorsement(Endorsement):
    BYTE_FORMAT = '16s240sII64s'
    BYTE_FORMAT_NOT_SIGNED = '16s240sII'

    def __init__(
        self,
        hhit: str,
        generic_endorsement: str | GenericEndorsement,
        vnb: int,
        vna: int,
        signature: t.Optional[t.Dict[str, str]] = None
    ):
        super().__init__(
            identity={'hhit': hhit},
            evidence=[generic_endorsement if isinstance(generic_endorsement, str) else generic_endorsement.toBytes().hex()],
            scope={'vnb': vnb, 'vna': vna},
            signature=signature
        )

    def toSignatureData(self) -> bytes:
        return super().toSignatureData(self.BYTE_FORMAT_NOT_SIGNED)

    def sign(self, key: bytes, signature_type: SignatureType):
        sig, b16, b64 = sign(key, signature_type, self.toSignatureData())
        self.signature = {'sig_b16': b16}

    def toBytes(self) -> bytes:
        return super().toBytes(self.BYTE_FORMAT)

    @classmethod
    def fromBytes(cls, endorsement_bytes: bytes):
        try:
            hhit, generic_endorsement, vnb, vna, signature = struct.unpack(cls.BYTE_FORMAT, endorsement_bytes)
            return MutualEndorsement(
                hhit=hhit.hex(),
                generic_endorsement=generic_endorsement.hex(),
                vnb=vnb,
                vna=vna,
                signature={'sig_b16': signature.hex()}
            )
        except struct.error as e:
            raise Exception('Unable to create a Mutual Endorsement from bytes, details:', e)


class LinkEndorsement(Endorsement):
    BYTE_FORMAT = '16s104sII64s'
    BYTE_FORMAT_NOT_SIGNED = '16s104sII'

    def __init__(
        self,
        hhit: str,
        concise_endorsement: str | ConciseEndorsement,
        vnb: int,
        vna: int,
        signature: t.Optional[t.Dict[str, str]] = None
    ):
        super().__init__(
            identity={'hhit': hhit},
            evidence=[concise_endorsement if isinstance(concise_endorsement, str) else concise_endorsement.toBytes().hex()],
            scope={'vnb': vnb, 'vna': vna},
            signature=signature
        )

    def toSignatureData(self) -> bytes:
        return super().toSignatureData(self.BYTE_FORMAT_NOT_SIGNED)

    def sign(self, key: bytes, signature_type: SignatureType):
        sig, b16, b64 = sign(key, signature_type, self.toSignatureData())
        self.signature = {'sig_b16': b16}

    def toBytes(self) -> bytes:
        return super().toBytes(self.BYTE_FORMAT)

    @classmethod
    def fromBytes(cls, endorsement_bytes: bytes):
        try:
            hhit, concise_endorsement, vnb, vna, signature = struct.unpack(cls.BYTE_FORMAT, endorsement_bytes)
            return LinkEndorsement(
                hhit=hhit.hex(),
                concise_endorsement=concise_endorsement.hex(),
                vnb=vnb,
                vna=vna,
                signature={'sig_b16': signature.hex()}
            )
        except struct.error as e:
            raise Exception('Unable to create a Link Endorsement from bytes, details:', e)


class BroadcastEndorsement(Endorsement):
    BYTE_FORMAT = '16s16s32sII64s'
    BYTE_FORMAT_NOT_SIGNED = '16s16s32sII'

    def __init__(
        self,
        hhit_1: str,
        hhit_2: str,
        host_identity: str,
        vnb: int,
        vna: int,
        signature: t.Optional[t.Dict[str, str]] = None
    ):
        super().__init__(
            identity={'hhit': hhit_1},
            evidence=[hhit_2, host_identity],
            scope={'vnb': vnb, 'vna': vna},
            signature=signature
        )

    def toSignatureData(self) -> bytes:
        return super().toSignatureData(self.BYTE_FORMAT_NOT_SIGNED)

    def sign(self, key: bytes, signature_type: SignatureType):
        sig, b16, b64 = sign(key, signature_type, self.toSignatureData())
        self.signature = {'sig_b16': b16}

    def toBytes(self) -> bytes:
        return super().toBytes(self.BYTE_FORMAT)

    @classmethod
    def fromBytes(cls, endorsement_bytes: bytes):
        try:
            hhit_1, hhit_2, host_identity, vnb, vna, signature = struct.unpack(cls.BYTE_FORMAT, endorsement_bytes)
            return BroadcastEndorsement(
                hhit_1=hhit_1.hex(),
                hhit_2=hhit_2.hex(),
                host_identity=host_identity.hex(),
                vnb=vnb,
                vna=vna,
                signature={'sig_b16': signature.hex()}
            )
        except struct.error as e:
            raise Exception('Unable to create a Broadcast Endorsement from bytes, details:', e)
