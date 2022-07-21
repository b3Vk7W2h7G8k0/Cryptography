# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import abc
import datetime
import hashlib
import ipaddress
import typing

from cryptography import utils
from cryptography.hazmat.bindings._rust import asn1
from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.hazmat.primitives import constant_time, serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES,
    CERTIFICATE_PUBLIC_KEY_TYPES,
)
from cryptography.x509.certificate_transparency import (
    SignedCertificateTimestamp,
)
from cryptography.x509.general_name import (
    DNSName,
    DirectoryName,
    GeneralName,
    IPAddress,
    OtherName,
    RFC822Name,
    RegisteredID,
    UniformResourceIdentifier,
    _IPADDRESS_TYPES,
)
from cryptography.x509.name import Name, RelativeDistinguishedName
from cryptography.x509.oid import (
    CRLEntryExtensionOID,
    ExtensionOID,
    OCSPExtensionOID,
    ObjectIdentifier,
)

ExtensionTypeVar = typing.TypeVar(
    "ExtensionTypeVar", bound="ExtensionType", covariant=True
)


def _key_identifier_from_public_key(
    public_key: CERTIFICATE_PUBLIC_KEY_TYPES,
) -> bytes:
    if isinstance(public_key, RSAPublicKey):
        data = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1,
        )
    elif isinstance(public_key, EllipticCurvePublicKey):
        data = public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    else:
        # This is a very slow way to do this.
        serialized = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        data = asn1.parse_spki_for_data(serialized)

    return hashlib.sha1(data).digest()


def _make_sequence_methods(field_name: str):
    def len_method(self) -> int:
        return len(getattr(self, field_name))

    def iter_method(self):
        return iter(getattr(self, field_name))

    def getitem_method(self, idx):
        return getattr(self, field_name)[idx]

    return len_method, iter_method, getitem_method


class DuplicateExtension(Exception):
    def __init__(self, msg: str, oid: ObjectIdentifier) -> None:
        super(DuplicateExtension, self).__init__(msg)
        self.oid = oid


class ExtensionNotFound(Exception):
    def __init__(self, msg: str, oid: ObjectIdentifier) -> None:
        super(ExtensionNotFound, self).__init__(msg)
        self.oid = oid


class ExtensionType(metaclass=abc.ABCMeta):
    oid: typing.ClassVar[ObjectIdentifier]

    def public_bytes(self) -> bytes:
        """
        Serializes the extension type to DER.
        """
        raise NotImplementedError(
            "public_bytes is not implemented for extension type {0!r}".format(
                self
            )
        )


class Extensions:
    def __init__(
        self, extensions: typing.Iterable["Extension[ExtensionType]"]
    ) -> None:
        self._extensions = list(extensions)

    def get_extension_for_oid(
        self, oid: ObjectIdentifier
    ) -> "Extension[ExtensionType]":
        for ext in self:
            if ext.oid == oid:
                return ext

        raise ExtensionNotFound("No {} extension was found".format(oid), oid)

    def get_extension_for_class(
        self, extclass: typing.Type[ExtensionTypeVar]
    ) -> "Extension[ExtensionTypeVar]":
        if extclass is UnrecognizedExtension:
            raise TypeError(
                "UnrecognizedExtension can't be used with "
                "get_extension_for_class because more than one instance of the"
                " class may be present."
            )

        for ext in self:
            if isinstance(ext.value, extclass):
                return ext

        raise ExtensionNotFound(
            "No {} extension was found".format(extclass), extclass.oid
        )

    __len__, __iter__, __getitem__ = _make_sequence_methods("_extensions")

    def __repr__(self) -> str:
        return "<Extensions({})>".format(self._extensions)


class CRLNumber(ExtensionType):
    oid = ExtensionOID.CRL_NUMBER

    def __init__(self, crl_number: int) -> None:
        if not isinstance(crl_number, int):
            raise TypeError("crl_number must be an integer")

        self._crl_number = crl_number

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CRLNumber):
            return NotImplemented

        return self.crl_number == other.crl_number

    def __hash__(self) -> int:
        return hash(self.crl_number)

    def __repr__(self) -> str:
        return "<CRLNumber({})>".format(self.crl_number)

    @property
    def crl_number(self) -> int:
        return self._crl_number

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class AuthorityKeyIdentifier(ExtensionType):
    oid = ExtensionOID.AUTHORITY_KEY_IDENTIFIER

    def __init__(
        self,
        key_identifier: typing.Optional[bytes],
        authority_cert_issuer: typing.Optional[typing.Iterable[GeneralName]],
        authority_cert_serial_number: typing.Optional[int],
    ) -> None:
        if (authority_cert_issuer is None) != (
            authority_cert_serial_number is None
        ):
            raise ValueError(
                "authority_cert_issuer and authority_cert_serial_number "
                "must both be present or both None"
            )

        if authority_cert_issuer is not None:
            authority_cert_issuer = list(authority_cert_issuer)
            if not all(
                isinstance(x, GeneralName) for x in authority_cert_issuer
            ):
                raise TypeError(
                    "authority_cert_issuer must be a list of GeneralName "
                    "objects"
                )

        if authority_cert_serial_number is not None and not isinstance(
            authority_cert_serial_number, int
        ):
            raise TypeError("authority_cert_serial_number must be an integer")

        self._key_identifier = key_identifier
        self._authority_cert_issuer = authority_cert_issuer
        self._authority_cert_serial_number = authority_cert_serial_number

    # This takes a subset of CERTIFICATE_PUBLIC_KEY_TYPES because an issuer
    # cannot have an X25519/X448 key. This introduces some unfortunate
    # asymmetry that requires typing users to explicitly
    # narrow their type, but we should make this accurate and not just
    # convenient.
    @classmethod
    def from_issuer_public_key(
        cls, public_key: CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES
    ) -> "AuthorityKeyIdentifier":
        digest = _key_identifier_from_public_key(public_key)
        return cls(
            key_identifier=digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )

    @classmethod
    def from_issuer_subject_key_identifier(
        cls, ski: "SubjectKeyIdentifier"
    ) -> "AuthorityKeyIdentifier":
        return cls(
            key_identifier=ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )

    def __repr__(self) -> str:
        return (
            "<AuthorityKeyIdentifier(key_identifier={0.key_identifier!r}, "
            "authority_cert_issuer={0.authority_cert_issuer}, "
            "authority_cert_serial_number={0.authority_cert_serial_number}"
            ")>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuthorityKeyIdentifier):
            return NotImplemented

        return (
            self.key_identifier == other.key_identifier
            and self.authority_cert_issuer == other.authority_cert_issuer
            and self.authority_cert_serial_number
            == other.authority_cert_serial_number
        )

    def __hash__(self) -> int:
        if self.authority_cert_issuer is None:
            aci = None
        else:
            aci = tuple(self.authority_cert_issuer)
        return hash(
            (self.key_identifier, aci, self.authority_cert_serial_number)
        )

    @property
    def key_identifier(self) -> typing.Optional[bytes]:
        return self._key_identifier

    @property
    def authority_cert_issuer(
        self,
    ) -> typing.Optional[typing.List[GeneralName]]:
        return self._authority_cert_issuer

    @property
    def authority_cert_serial_number(self) -> typing.Optional[int]:
        return self._authority_cert_serial_number

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class SubjectKeyIdentifier(ExtensionType):
    oid = ExtensionOID.SUBJECT_KEY_IDENTIFIER

    def __init__(self, digest: bytes) -> None:
        self._digest = digest

    @classmethod
    def from_public_key(
        cls, public_key: CERTIFICATE_PUBLIC_KEY_TYPES
    ) -> "SubjectKeyIdentifier":
        return cls(_key_identifier_from_public_key(public_key))

    @property
    def digest(self) -> bytes:
        return self._digest

    @property
    def key_identifier(self) -> bytes:
        return self._digest

    def __repr__(self) -> str:
        return "<SubjectKeyIdentifier(digest={0!r})>".format(self.digest)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SubjectKeyIdentifier):
            return NotImplemented

        return constant_time.bytes_eq(self.digest, other.digest)

    def __hash__(self) -> int:
        return hash(self.digest)

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class AuthorityInformationAccess(ExtensionType):
    oid = ExtensionOID.AUTHORITY_INFORMATION_ACCESS

    def __init__(
        self, descriptions: typing.Iterable["AccessDescription"]
    ) -> None:
        descriptions = list(descriptions)
        if not all(isinstance(x, AccessDescription) for x in descriptions):
            raise TypeError(
                "Every item in the descriptions list must be an "
                "AccessDescription"
            )

        self._descriptions = descriptions

    __len__, __iter__, __getitem__ = _make_sequence_methods("_descriptions")

    def __repr__(self) -> str:
        return "<AuthorityInformationAccess({})>".format(self._descriptions)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuthorityInformationAccess):
            return NotImplemented

        return self._descriptions == other._descriptions

    def __hash__(self) -> int:
        return hash(tuple(self._descriptions))

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class SubjectInformationAccess(ExtensionType):
    oid = ExtensionOID.SUBJECT_INFORMATION_ACCESS

    def __init__(
        self, descriptions: typing.Iterable["AccessDescription"]
    ) -> None:
        descriptions = list(descriptions)
        if not all(isinstance(x, AccessDescription) for x in descriptions):
            raise TypeError(
                "Every item in the descriptions list must be an "
                "AccessDescription"
            )

        self._descriptions = descriptions

    __len__, __iter__, __getitem__ = _make_sequence_methods("_descriptions")

    def __repr__(self) -> str:
        return "<SubjectInformationAccess({})>".format(self._descriptions)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SubjectInformationAccess):
            return NotImplemented

        return self._descriptions == other._descriptions

    def __hash__(self) -> int:
        return hash(tuple(self._descriptions))

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class AccessDescription:
    def __init__(
        self, access_method: ObjectIdentifier, access_location: GeneralName
    ) -> None:
        if not isinstance(access_method, ObjectIdentifier):
            raise TypeError("access_method must be an ObjectIdentifier")

        if not isinstance(access_location, GeneralName):
            raise TypeError("access_location must be a GeneralName")

        self._access_method = access_method
        self._access_location = access_location

    def __repr__(self) -> str:
        return (
            "<AccessDescription(access_method={0.access_method}, access_locati"
            "on={0.access_location})>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AccessDescription):
            return NotImplemented

        return (
            self.access_method == other.access_method
            and self.access_location == other.access_location
        )

    def __hash__(self) -> int:
        return hash((self.access_method, self.access_location))

    @property
    def access_method(self) -> ObjectIdentifier:
        return self._access_method

    @property
    def access_location(self) -> GeneralName:
        return self._access_location


class BasicConstraints(ExtensionType):
    oid = ExtensionOID.BASIC_CONSTRAINTS

    def __init__(self, ca: bool, path_length: typing.Optional[int]) -> None:
        if not isinstance(ca, bool):
            raise TypeError("ca must be a boolean value")

        if path_length is not None and not ca:
            raise ValueError("path_length must be None when ca is False")

        if path_length is not None and (
            not isinstance(path_length, int) or path_length < 0
        ):
            raise TypeError(
                "path_length must be a non-negative integer or None"
            )

        self._ca = ca
        self._path_length = path_length

    @property
    def ca(self) -> bool:
        return self._ca

    @property
    def path_length(self) -> typing.Optional[int]:
        return self._path_length

    def __repr__(self) -> str:
        return (
            "<BasicConstraints(ca={0.ca}, " "path_length={0.path_length})>"
        ).format(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BasicConstraints):
            return NotImplemented

        return self.ca == other.ca and self.path_length == other.path_length

    def __hash__(self) -> int:
        return hash((self.ca, self.path_length))

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class DeltaCRLIndicator(ExtensionType):
    oid = ExtensionOID.DELTA_CRL_INDICATOR

    def __init__(self, crl_number: int) -> None:
        if not isinstance(crl_number, int):
            raise TypeError("crl_number must be an integer")

        self._crl_number = crl_number

    @property
    def crl_number(self) -> int:
        return self._crl_number

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DeltaCRLIndicator):
            return NotImplemented

        return self.crl_number == other.crl_number

    def __hash__(self) -> int:
        return hash(self.crl_number)

    def __repr__(self) -> str:
        return "<DeltaCRLIndicator(crl_number={0.crl_number})>".format(self)

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class CRLDistributionPoints(ExtensionType):
    oid = ExtensionOID.CRL_DISTRIBUTION_POINTS

    def __init__(
        self, distribution_points: typing.Iterable["DistributionPoint"]
    ) -> None:
        distribution_points = list(distribution_points)
        if not all(
            isinstance(x, DistributionPoint) for x in distribution_points
        ):
            raise TypeError(
                "distribution_points must be a list of DistributionPoint "
                "objects"
            )

        self._distribution_points = distribution_points

    __len__, __iter__, __getitem__ = _make_sequence_methods(
        "_distribution_points"
    )

    def __repr__(self) -> str:
        return "<CRLDistributionPoints({})>".format(self._distribution_points)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CRLDistributionPoints):
            return NotImplemented

        return self._distribution_points == other._distribution_points

    def __hash__(self) -> int:
        return hash(tuple(self._distribution_points))

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class FreshestCRL(ExtensionType):
    oid = ExtensionOID.FRESHEST_CRL

    def __init__(
        self, distribution_points: typing.Iterable["DistributionPoint"]
    ) -> None:
        distribution_points = list(distribution_points)
        if not all(
            isinstance(x, DistributionPoint) for x in distribution_points
        ):
            raise TypeError(
                "distribution_points must be a list of DistributionPoint "
                "objects"
            )

        self._distribution_points = distribution_points

    __len__, __iter__, __getitem__ = _make_sequence_methods(
        "_distribution_points"
    )

    def __repr__(self) -> str:
        return "<FreshestCRL({})>".format(self._distribution_points)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FreshestCRL):
            return NotImplemented

        return self._distribution_points == other._distribution_points

    def __hash__(self) -> int:
        return hash(tuple(self._distribution_points))

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class DistributionPoint:
    def __init__(
        self,
        full_name: typing.Optional[typing.Iterable[GeneralName]],
        relative_name: typing.Optional[RelativeDistinguishedName],
        reasons: typing.Optional[typing.FrozenSet["ReasonFlags"]],
        crl_issuer: typing.Optional[typing.Iterable[GeneralName]],
    ) -> None:
        if full_name and relative_name:
            raise ValueError(
                "You cannot provide both full_name and relative_name, at "
                "least one must be None."
            )

        if full_name is not None:
            full_name = list(full_name)
            if not all(isinstance(x, GeneralName) for x in full_name):
                raise TypeError(
                    "full_name must be a list of GeneralName objects"
                )

        if relative_name:
            if not isinstance(relative_name, RelativeDistinguishedName):
                raise TypeError(
                    "relative_name must be a RelativeDistinguishedName"
                )

        if crl_issuer is not None:
            crl_issuer = list(crl_issuer)
            if not all(isinstance(x, GeneralName) for x in crl_issuer):
                raise TypeError(
                    "crl_issuer must be None or a list of general names"
                )

        if reasons and (
            not isinstance(reasons, frozenset)
            or not all(isinstance(x, ReasonFlags) for x in reasons)
        ):
            raise TypeError("reasons must be None or frozenset of ReasonFlags")

        if reasons and (
            ReasonFlags.unspecified in reasons
            or ReasonFlags.remove_from_crl in reasons
        ):
            raise ValueError(
                "unspecified and remove_from_crl are not valid reasons in a "
                "DistributionPoint"
            )

        if reasons and not crl_issuer and not (full_name or relative_name):
            raise ValueError(
                "You must supply crl_issuer, full_name, or relative_name when "
                "reasons is not None"
            )

        self._full_name = full_name
        self._relative_name = relative_name
        self._reasons = reasons
        self._crl_issuer = crl_issuer

    def __repr__(self) -> str:
        return (
            "<DistributionPoint(full_name={0.full_name}, relative_name={0.rela"
            "tive_name}, reasons={0.reasons}, "
            "crl_issuer={0.crl_issuer})>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DistributionPoint):
            return NotImplemented

        return (
            self.full_name == other.full_name
            and self.relative_name == other.relative_name
            and self.reasons == other.reasons
            and self.crl_issuer == other.crl_issuer
        )

    def __hash__(self) -> int:
        if self.full_name is not None:
            fn: typing.Optional[typing.Tuple[GeneralName, ...]] = tuple(
                self.full_name
            )
        else:
            fn = None

        if self.crl_issuer is not None:
            crl_issuer: typing.Optional[
                typing.Tuple[GeneralName, ...]
            ] = tuple(self.crl_issuer)
        else:
            crl_issuer = None

        return hash((fn, self.relative_name, self.reasons, crl_issuer))

    @property
    def full_name(self) -> typing.Optional[typing.List[GeneralName]]:
        return self._full_name

    @property
    def relative_name(self) -> typing.Optional[RelativeDistinguishedName]:
        return self._relative_name

    @property
    def reasons(self) -> typing.Optional[typing.FrozenSet["ReasonFlags"]]:
        return self._reasons

    @property
    def crl_issuer(self) -> typing.Optional[typing.List[GeneralName]]:
        return self._crl_issuer


class ReasonFlags(utils.Enum):
    unspecified = "unspecified"
    key_compromise = "keyCompromise"
    ca_compromise = "cACompromise"
    affiliation_changed = "affiliationChanged"
    superseded = "superseded"
    cessation_of_operation = "cessationOfOperation"
    certificate_hold = "certificateHold"
    privilege_withdrawn = "privilegeWithdrawn"
    aa_compromise = "aACompromise"
    remove_from_crl = "removeFromCRL"


# These are distribution point bit string mappings. Not to be confused with
# CRLReason reason flags bit string mappings.
# ReasonFlags ::= BIT STRING {
#      unused                  (0),
#      keyCompromise           (1),
#      cACompromise            (2),
#      affiliationChanged      (3),
#      superseded              (4),
#      cessationOfOperation    (5),
#      certificateHold         (6),
#      privilegeWithdrawn      (7),
#      aACompromise            (8) }
_REASON_BIT_MAPPING = {
    1: ReasonFlags.key_compromise,
    2: ReasonFlags.ca_compromise,
    3: ReasonFlags.affiliation_changed,
    4: ReasonFlags.superseded,
    5: ReasonFlags.cessation_of_operation,
    6: ReasonFlags.certificate_hold,
    7: ReasonFlags.privilege_withdrawn,
    8: ReasonFlags.aa_compromise,
}

_CRLREASONFLAGS = {
    ReasonFlags.key_compromise: 1,
    ReasonFlags.ca_compromise: 2,
    ReasonFlags.affiliation_changed: 3,
    ReasonFlags.superseded: 4,
    ReasonFlags.cessation_of_operation: 5,
    ReasonFlags.certificate_hold: 6,
    ReasonFlags.privilege_withdrawn: 7,
    ReasonFlags.aa_compromise: 8,
}


class PolicyConstraints(ExtensionType):
    oid = ExtensionOID.POLICY_CONSTRAINTS

    def __init__(
        self,
        require_explicit_policy: typing.Optional[int],
        inhibit_policy_mapping: typing.Optional[int],
    ) -> None:
        if require_explicit_policy is not None and not isinstance(
            require_explicit_policy, int
        ):
            raise TypeError(
                "require_explicit_policy must be a non-negative integer or "
                "None"
            )

        if inhibit_policy_mapping is not None and not isinstance(
            inhibit_policy_mapping, int
        ):
            raise TypeError(
                "inhibit_policy_mapping must be a non-negative integer or None"
            )

        if inhibit_policy_mapping is None and require_explicit_policy is None:
            raise ValueError(
                "At least one of require_explicit_policy and "
                "inhibit_policy_mapping must not be None"
            )

        self._require_explicit_policy = require_explicit_policy
        self._inhibit_policy_mapping = inhibit_policy_mapping

    def __repr__(self) -> str:
        return (
            "<PolicyConstraints(require_explicit_policy={0.require_explicit"
            "_policy}, inhibit_policy_mapping={0.inhibit_policy_"
            "mapping})>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PolicyConstraints):
            return NotImplemented

        return (
            self.require_explicit_policy == other.require_explicit_policy
            and self.inhibit_policy_mapping == other.inhibit_policy_mapping
        )

    def __hash__(self) -> int:
        return hash(
            (self.require_explicit_policy, self.inhibit_policy_mapping)
        )

    @property
    def require_explicit_policy(self) -> typing.Optional[int]:
        return self._require_explicit_policy

    @property
    def inhibit_policy_mapping(self) -> typing.Optional[int]:
        return self._inhibit_policy_mapping

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class CertificatePolicies(ExtensionType):
    oid = ExtensionOID.CERTIFICATE_POLICIES

    def __init__(self, policies: typing.Iterable["PolicyInformation"]) -> None:
        policies = list(policies)
        if not all(isinstance(x, PolicyInformation) for x in policies):
            raise TypeError(
                "Every item in the policies list must be a "
                "PolicyInformation"
            )

        self._policies = policies

    __len__, __iter__, __getitem__ = _make_sequence_methods("_policies")

    def __repr__(self) -> str:
        return "<CertificatePolicies({})>".format(self._policies)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CertificatePolicies):
            return NotImplemented

        return self._policies == other._policies

    def __hash__(self) -> int:
        return hash(tuple(self._policies))

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class PolicyInformation:
    def __init__(
        self,
        policy_identifier: ObjectIdentifier,
        policy_qualifiers: typing.Optional[
            typing.Iterable[typing.Union[str, "UserNotice"]]
        ],
    ) -> None:
        if not isinstance(policy_identifier, ObjectIdentifier):
            raise TypeError("policy_identifier must be an ObjectIdentifier")

        self._policy_identifier = policy_identifier

        if policy_qualifiers is not None:
            policy_qualifiers = list(policy_qualifiers)
            if not all(
                isinstance(x, (str, UserNotice)) for x in policy_qualifiers
            ):
                raise TypeError(
                    "policy_qualifiers must be a list of strings and/or "
                    "UserNotice objects or None"
                )

        self._policy_qualifiers = policy_qualifiers

    def __repr__(self) -> str:
        return (
            "<PolicyInformation(policy_identifier={0.policy_identifier}, polic"
            "y_qualifiers={0.policy_qualifiers})>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PolicyInformation):
            return NotImplemented

        return (
            self.policy_identifier == other.policy_identifier
            and self.policy_qualifiers == other.policy_qualifiers
        )

    def __hash__(self) -> int:
        if self.policy_qualifiers is not None:
            pq: typing.Optional[
                typing.Tuple[typing.Union[str, "UserNotice"], ...]
            ] = tuple(self.policy_qualifiers)
        else:
            pq = None

        return hash((self.policy_identifier, pq))

    @property
    def policy_identifier(self) -> ObjectIdentifier:
        return self._policy_identifier

    @property
    def policy_qualifiers(
        self,
    ) -> typing.Optional[typing.List[typing.Union[str, "UserNotice"]]]:
        return self._policy_qualifiers


class UserNotice:
    def __init__(
        self,
        notice_reference: typing.Optional["NoticeReference"],
        explicit_text: typing.Optional[str],
    ) -> None:
        if notice_reference and not isinstance(
            notice_reference, NoticeReference
        ):
            raise TypeError(
                "notice_reference must be None or a NoticeReference"
            )

        self._notice_reference = notice_reference
        self._explicit_text = explicit_text

    def __repr__(self) -> str:
        return (
            "<UserNotice(notice_reference={0.notice_reference}, explicit_text="
            "{0.explicit_text!r})>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UserNotice):
            return NotImplemented

        return (
            self.notice_reference == other.notice_reference
            and self.explicit_text == other.explicit_text
        )

    def __hash__(self) -> int:
        return hash((self.notice_reference, self.explicit_text))

    @property
    def notice_reference(self) -> typing.Optional["NoticeReference"]:
        return self._notice_reference

    @property
    def explicit_text(self) -> typing.Optional[str]:
        return self._explicit_text


class NoticeReference:
    def __init__(
        self,
        organization: typing.Optional[str],
        notice_numbers: typing.Iterable[int],
    ) -> None:
        self._organization = organization
        notice_numbers = list(notice_numbers)
        if not all(isinstance(x, int) for x in notice_numbers):
            raise TypeError("notice_numbers must be a list of integers")

        self._notice_numbers = notice_numbers

    def __repr__(self) -> str:
        return (
            "<NoticeReference(organization={0.organization!r}, notice_numbers="
            "{0.notice_numbers})>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NoticeReference):
            return NotImplemented

        return (
            self.organization == other.organization
            and self.notice_numbers == other.notice_numbers
        )

    def __hash__(self) -> int:
        return hash((self.organization, tuple(self.notice_numbers)))

    @property
    def organization(self) -> typing.Optional[str]:
        return self._organization

    @property
    def notice_numbers(self) -> typing.List[int]:
        return self._notice_numbers


class ExtendedKeyUsage(ExtensionType):
    oid = ExtensionOID.EXTENDED_KEY_USAGE

    def __init__(self, usages: typing.Iterable[ObjectIdentifier]) -> None:
        usages = list(usages)
        if not all(isinstance(x, ObjectIdentifier) for x in usages):
            raise TypeError(
                "Every item in the usages list must be an ObjectIdentifier"
            )

        self._usages = usages

    __len__, __iter__, __getitem__ = _make_sequence_methods("_usages")

    def __repr__(self) -> str:
        return "<ExtendedKeyUsage({})>".format(self._usages)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExtendedKeyUsage):
            return NotImplemented

        return self._usages == other._usages

    def __hash__(self) -> int:
        return hash(tuple(self._usages))

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class OCSPNoCheck(ExtensionType):
    oid = ExtensionOID.OCSP_NO_CHECK

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OCSPNoCheck):
            return NotImplemented

        return True

    def __hash__(self) -> int:
        return hash(OCSPNoCheck)

    def __repr__(self) -> str:
        return "<OCSPNoCheck()>"

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class PrecertPoison(ExtensionType):
    oid = ExtensionOID.PRECERT_POISON

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PrecertPoison):
            return NotImplemented

        return True

    def __hash__(self) -> int:
        return hash(PrecertPoison)

    def __repr__(self) -> str:
        return "<PrecertPoison()>"

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class TLSFeature(ExtensionType):
    oid = ExtensionOID.TLS_FEATURE

    def __init__(self, features: typing.Iterable["TLSFeatureType"]) -> None:
        features = list(features)
        if (
            not all(isinstance(x, TLSFeatureType) for x in features)
            or len(features) == 0
        ):
            raise TypeError(
                "features must be a list of elements from the TLSFeatureType "
                "enum"
            )

        self._features = features

    __len__, __iter__, __getitem__ = _make_sequence_methods("_features")

    def __repr__(self) -> str:
        return "<TLSFeature(features={0._features})>".format(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TLSFeature):
            return NotImplemented

        return self._features == other._features

    def __hash__(self) -> int:
        return hash(tuple(self._features))

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class TLSFeatureType(utils.Enum):
    # status_request is defined in RFC 6066 and is used for what is commonly
    # called OCSP Must-Staple when present in the TLS Feature extension in an
    # X.509 certificate.
    status_request = 5
    # status_request_v2 is defined in RFC 6961 and allows multiple OCSP
    # responses to be provided. It is not currently in use by clients or
    # servers.
    status_request_v2 = 17


_TLS_FEATURE_TYPE_TO_ENUM = {x.value: x for x in TLSFeatureType}


class InhibitAnyPolicy(ExtensionType):
    oid = ExtensionOID.INHIBIT_ANY_POLICY

    def __init__(self, skip_certs: int) -> None:
        if not isinstance(skip_certs, int):
            raise TypeError("skip_certs must be an integer")

        if skip_certs < 0:
            raise ValueError("skip_certs must be a non-negative integer")

        self._skip_certs = skip_certs

    def __repr__(self) -> str:
        return "<InhibitAnyPolicy(skip_certs={0.skip_certs})>".format(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, InhibitAnyPolicy):
            return NotImplemented

        return self.skip_certs == other.skip_certs

    def __hash__(self) -> int:
        return hash(self.skip_certs)

    @property
    def skip_certs(self) -> int:
        return self._skip_certs

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class KeyUsage(ExtensionType):
    oid = ExtensionOID.KEY_USAGE

    def __init__(
        self,
        digital_signature: bool,
        content_commitment: bool,
        key_encipherment: bool,
        data_encipherment: bool,
        key_agreement: bool,
        key_cert_sign: bool,
        crl_sign: bool,
        encipher_only: bool,
        decipher_only: bool,
    ) -> None:
        if not key_agreement and (encipher_only or decipher_only):
            raise ValueError(
                "encipher_only and decipher_only can only be true when "
                "key_agreement is true"
            )

        self._digital_signature = digital_signature
        self._content_commitment = content_commitment
        self._key_encipherment = key_encipherment
        self._data_encipherment = data_encipherment
        self._key_agreement = key_agreement
        self._key_cert_sign = key_cert_sign
        self._crl_sign = crl_sign
        self._encipher_only = encipher_only
        self._decipher_only = decipher_only

    @property
    def digital_signature(self) -> bool:
        return self._digital_signature

    @property
    def content_commitment(self) -> bool:
        return self._content_commitment

    @property
    def key_encipherment(self) -> bool:
        return self._key_encipherment

    @property
    def data_encipherment(self) -> bool:
        return self._data_encipherment

    @property
    def key_agreement(self) -> bool:
        return self._key_agreement

    @property
    def key_cert_sign(self) -> bool:
        return self._key_cert_sign

    @property
    def crl_sign(self) -> bool:
        return self._crl_sign

    @property
    def encipher_only(self) -> bool:
        if not self.key_agreement:
            raise ValueError(
                "encipher_only is undefined unless key_agreement is true"
            )
        else:
            return self._encipher_only

    @property
    def decipher_only(self) -> bool:
        if not self.key_agreement:
            raise ValueError(
                "decipher_only is undefined unless key_agreement is true"
            )
        else:
            return self._decipher_only

    def __repr__(self) -> str:
        try:
            encipher_only = self.encipher_only
            decipher_only = self.decipher_only
        except ValueError:
            # Users found None confusing because even though encipher/decipher
            # have no meaning unless key_agreement is true, to construct an
            # instance of the class you still need to pass False.
            encipher_only = False
            decipher_only = False

        return (
            "<KeyUsage(digital_signature={0.digital_signature}, "
            "content_commitment={0.content_commitment}, "
            "key_encipherment={0.key_encipherment}, "
            "data_encipherment={0.data_encipherment}, "
            "key_agreement={0.key_agreement}, "
            "key_cert_sign={0.key_cert_sign}, crl_sign={0.crl_sign}, "
            "encipher_only={1}, decipher_only={2})>"
        ).format(self, encipher_only, decipher_only)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyUsage):
            return NotImplemented

        return (
            self.digital_signature == other.digital_signature
            and self.content_commitment == other.content_commitment
            and self.key_encipherment == other.key_encipherment
            and self.data_encipherment == other.data_encipherment
            and self.key_agreement == other.key_agreement
            and self.key_cert_sign == other.key_cert_sign
            and self.crl_sign == other.crl_sign
            and self._encipher_only == other._encipher_only
            and self._decipher_only == other._decipher_only
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.digital_signature,
                self.content_commitment,
                self.key_encipherment,
                self.data_encipherment,
                self.key_agreement,
                self.key_cert_sign,
                self.crl_sign,
                self._encipher_only,
                self._decipher_only,
            )
        )

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class NameConstraints(ExtensionType):
    oid = ExtensionOID.NAME_CONSTRAINTS

    def __init__(
        self,
        permitted_subtrees: typing.Optional[typing.Iterable[GeneralName]],
        excluded_subtrees: typing.Optional[typing.Iterable[GeneralName]],
    ) -> None:
        if permitted_subtrees is not None:
            permitted_subtrees = list(permitted_subtrees)
            if not permitted_subtrees:
                raise ValueError(
                    "permitted_subtrees must be a non-empty list or None"
                )
            if not all(isinstance(x, GeneralName) for x in permitted_subtrees):
                raise TypeError(
                    "permitted_subtrees must be a list of GeneralName objects "
                    "or None"
                )

            self._validate_ip_name(permitted_subtrees)

        if excluded_subtrees is not None:
            excluded_subtrees = list(excluded_subtrees)
            if not excluded_subtrees:
                raise ValueError(
                    "excluded_subtrees must be a non-empty list or None"
                )
            if not all(isinstance(x, GeneralName) for x in excluded_subtrees):
                raise TypeError(
                    "excluded_subtrees must be a list of GeneralName objects "
                    "or None"
                )

            self._validate_ip_name(excluded_subtrees)

        if permitted_subtrees is None and excluded_subtrees is None:
            raise ValueError(
                "At least one of permitted_subtrees and excluded_subtrees "
                "must not be None"
            )

        self._permitted_subtrees = permitted_subtrees
        self._excluded_subtrees = excluded_subtrees

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NameConstraints):
            return NotImplemented

        return (
            self.excluded_subtrees == other.excluded_subtrees
            and self.permitted_subtrees == other.permitted_subtrees
        )

    def _validate_ip_name(self, tree: typing.Iterable[GeneralName]) -> None:
        if any(
            isinstance(name, IPAddress)
            and not isinstance(
                name.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)
            )
            for name in tree
        ):
            raise TypeError(
                "IPAddress name constraints must be an IPv4Network or"
                " IPv6Network object"
            )

    def __repr__(self) -> str:
        return (
            "<NameConstraints(permitted_subtrees={0.permitted_subtrees}, "
            "excluded_subtrees={0.excluded_subtrees})>".format(self)
        )

    def __hash__(self) -> int:
        if self.permitted_subtrees is not None:
            ps: typing.Optional[typing.Tuple[GeneralName, ...]] = tuple(
                self.permitted_subtrees
            )
        else:
            ps = None

        if self.excluded_subtrees is not None:
            es: typing.Optional[typing.Tuple[GeneralName, ...]] = tuple(
                self.excluded_subtrees
            )
        else:
            es = None

        return hash((ps, es))

    @property
    def permitted_subtrees(
        self,
    ) -> typing.Optional[typing.List[GeneralName]]:
        return self._permitted_subtrees

    @property
    def excluded_subtrees(
        self,
    ) -> typing.Optional[typing.List[GeneralName]]:
        return self._excluded_subtrees

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class Extension(typing.Generic[ExtensionTypeVar]):
    def __init__(
        self, oid: ObjectIdentifier, critical: bool, value: ExtensionTypeVar
    ) -> None:
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError(
                "oid argument must be an ObjectIdentifier instance."
            )

        if not isinstance(critical, bool):
            raise TypeError("critical must be a boolean value")

        self._oid = oid
        self._critical = critical
        self._value = value

    @property
    def oid(self) -> ObjectIdentifier:
        return self._oid

    @property
    def critical(self) -> bool:
        return self._critical

    @property
    def value(self) -> ExtensionTypeVar:
        return self._value

    def __repr__(self) -> str:
        return (
            "<Extension(oid={0.oid}, critical={0.critical}, "
            "value={0.value})>"
        ).format(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Extension):
            return NotImplemented

        return (
            self.oid == other.oid
            and self.critical == other.critical
            and self.value == other.value
        )

    def __hash__(self) -> int:
        return hash((self.oid, self.critical, self.value))


class GeneralNames:
    def __init__(self, general_names: typing.Iterable[GeneralName]) -> None:
        general_names = list(general_names)
        if not all(isinstance(x, GeneralName) for x in general_names):
            raise TypeError(
                "Every item in the general_names list must be an "
                "object conforming to the GeneralName interface"
            )

        self._general_names = general_names

    __len__, __iter__, __getitem__ = _make_sequence_methods("_general_names")

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Union[
            typing.Type[DNSName],
            typing.Type[UniformResourceIdentifier],
            typing.Type[RFC822Name],
        ],
    ) -> typing.List[str]:
        ...

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Type[DirectoryName],
    ) -> typing.List[Name]:
        ...

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Type[RegisteredID],
    ) -> typing.List[ObjectIdentifier]:
        ...

    @typing.overload
    def get_values_for_type(
        self, type: typing.Type[IPAddress]
    ) -> typing.List[_IPADDRESS_TYPES]:
        ...

    @typing.overload
    def get_values_for_type(
        self, type: typing.Type[OtherName]
    ) -> typing.List[OtherName]:
        ...

    def get_values_for_type(
        self,
        type: typing.Union[
            typing.Type[DNSName],
            typing.Type[DirectoryName],
            typing.Type[IPAddress],
            typing.Type[OtherName],
            typing.Type[RFC822Name],
            typing.Type[RegisteredID],
            typing.Type[UniformResourceIdentifier],
        ],
    ) -> typing.Union[
        typing.List[_IPADDRESS_TYPES],
        typing.List[str],
        typing.List[OtherName],
        typing.List[Name],
        typing.List[ObjectIdentifier],
    ]:
        # Return the value of each GeneralName, except for OtherName instances
        # which we return directly because it has two important properties not
        # just one value.
        objs = (i for i in self if isinstance(i, type))
        if type != OtherName:
            return [i.value for i in objs]
        return list(objs)

    def __repr__(self) -> str:
        return "<GeneralNames({})>".format(self._general_names)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GeneralNames):
            return NotImplemented

        return self._general_names == other._general_names

    def __hash__(self) -> int:
        return hash(tuple(self._general_names))


class SubjectAlternativeName(ExtensionType):
    oid = ExtensionOID.SUBJECT_ALTERNATIVE_NAME

    def __init__(self, general_names: typing.Iterable[GeneralName]) -> None:
        self._general_names = GeneralNames(general_names)

    __len__, __iter__, __getitem__ = _make_sequence_methods("_general_names")

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Union[
            typing.Type[DNSName],
            typing.Type[UniformResourceIdentifier],
            typing.Type[RFC822Name],
        ],
    ) -> typing.List[str]:
        ...

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Type[DirectoryName],
    ) -> typing.List[Name]:
        ...

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Type[RegisteredID],
    ) -> typing.List[ObjectIdentifier]:
        ...

    @typing.overload
    def get_values_for_type(
        self, type: typing.Type[IPAddress]
    ) -> typing.List[_IPADDRESS_TYPES]:
        ...

    @typing.overload
    def get_values_for_type(
        self, type: typing.Type[OtherName]
    ) -> typing.List[OtherName]:
        ...

    def get_values_for_type(
        self,
        type: typing.Union[
            typing.Type[DNSName],
            typing.Type[DirectoryName],
            typing.Type[IPAddress],
            typing.Type[OtherName],
            typing.Type[RFC822Name],
            typing.Type[RegisteredID],
            typing.Type[UniformResourceIdentifier],
        ],
    ) -> typing.Union[
        typing.List[_IPADDRESS_TYPES],
        typing.List[str],
        typing.List[OtherName],
        typing.List[Name],
        typing.List[ObjectIdentifier],
    ]:
        return self._general_names.get_values_for_type(type)

    def __repr__(self) -> str:
        return "<SubjectAlternativeName({})>".format(self._general_names)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SubjectAlternativeName):
            return NotImplemented

        return self._general_names == other._general_names

    def __hash__(self) -> int:
        return hash(self._general_names)

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class IssuerAlternativeName(ExtensionType):
    oid = ExtensionOID.ISSUER_ALTERNATIVE_NAME

    def __init__(self, general_names: typing.Iterable[GeneralName]) -> None:
        self._general_names = GeneralNames(general_names)

    __len__, __iter__, __getitem__ = _make_sequence_methods("_general_names")

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Union[
            typing.Type[DNSName],
            typing.Type[UniformResourceIdentifier],
            typing.Type[RFC822Name],
        ],
    ) -> typing.List[str]:
        ...

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Type[DirectoryName],
    ) -> typing.List[Name]:
        ...

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Type[RegisteredID],
    ) -> typing.List[ObjectIdentifier]:
        ...

    @typing.overload
    def get_values_for_type(
        self, type: typing.Type[IPAddress]
    ) -> typing.List[_IPADDRESS_TYPES]:
        ...

    @typing.overload
    def get_values_for_type(
        self, type: typing.Type[OtherName]
    ) -> typing.List[OtherName]:
        ...

    def get_values_for_type(
        self,
        type: typing.Union[
            typing.Type[DNSName],
            typing.Type[DirectoryName],
            typing.Type[IPAddress],
            typing.Type[OtherName],
            typing.Type[RFC822Name],
            typing.Type[RegisteredID],
            typing.Type[UniformResourceIdentifier],
        ],
    ) -> typing.Union[
        typing.List[_IPADDRESS_TYPES],
        typing.List[str],
        typing.List[OtherName],
        typing.List[Name],
        typing.List[ObjectIdentifier],
    ]:
        return self._general_names.get_values_for_type(type)

    def __repr__(self) -> str:
        return "<IssuerAlternativeName({})>".format(self._general_names)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IssuerAlternativeName):
            return NotImplemented

        return self._general_names == other._general_names

    def __hash__(self) -> int:
        return hash(self._general_names)

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class CertificateIssuer(ExtensionType):
    oid = CRLEntryExtensionOID.CERTIFICATE_ISSUER

    def __init__(self, general_names: typing.Iterable[GeneralName]) -> None:
        self._general_names = GeneralNames(general_names)

    __len__, __iter__, __getitem__ = _make_sequence_methods("_general_names")

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Union[
            typing.Type[DNSName],
            typing.Type[UniformResourceIdentifier],
            typing.Type[RFC822Name],
        ],
    ) -> typing.List[str]:
        ...

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Type[DirectoryName],
    ) -> typing.List[Name]:
        ...

    @typing.overload
    def get_values_for_type(
        self,
        type: typing.Type[RegisteredID],
    ) -> typing.List[ObjectIdentifier]:
        ...

    @typing.overload
    def get_values_for_type(
        self, type: typing.Type[IPAddress]
    ) -> typing.List[_IPADDRESS_TYPES]:
        ...

    @typing.overload
    def get_values_for_type(
        self, type: typing.Type[OtherName]
    ) -> typing.List[OtherName]:
        ...

    def get_values_for_type(
        self,
        type: typing.Union[
            typing.Type[DNSName],
            typing.Type[DirectoryName],
            typing.Type[IPAddress],
            typing.Type[OtherName],
            typing.Type[RFC822Name],
            typing.Type[RegisteredID],
            typing.Type[UniformResourceIdentifier],
        ],
    ) -> typing.Union[
        typing.List[_IPADDRESS_TYPES],
        typing.List[str],
        typing.List[OtherName],
        typing.List[Name],
        typing.List[ObjectIdentifier],
    ]:
        return self._general_names.get_values_for_type(type)

    def __repr__(self) -> str:
        return "<CertificateIssuer({})>".format(self._general_names)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CertificateIssuer):
            return NotImplemented

        return self._general_names == other._general_names

    def __hash__(self) -> int:
        return hash(self._general_names)

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class CRLReason(ExtensionType):
    oid = CRLEntryExtensionOID.CRL_REASON

    def __init__(self, reason: ReasonFlags) -> None:
        if not isinstance(reason, ReasonFlags):
            raise TypeError("reason must be an element from ReasonFlags")

        self._reason = reason

    def __repr__(self) -> str:
        return "<CRLReason(reason={})>".format(self._reason)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CRLReason):
            return NotImplemented

        return self.reason == other.reason

    def __hash__(self) -> int:
        return hash(self.reason)

    @property
    def reason(self) -> ReasonFlags:
        return self._reason

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class InvalidityDate(ExtensionType):
    oid = CRLEntryExtensionOID.INVALIDITY_DATE

    def __init__(self, invalidity_date: datetime.datetime) -> None:
        if not isinstance(invalidity_date, datetime.datetime):
            raise TypeError("invalidity_date must be a datetime.datetime")

        self._invalidity_date = invalidity_date

    def __repr__(self) -> str:
        return "<InvalidityDate(invalidity_date={})>".format(
            self._invalidity_date
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, InvalidityDate):
            return NotImplemented

        return self.invalidity_date == other.invalidity_date

    def __hash__(self) -> int:
        return hash(self.invalidity_date)

    @property
    def invalidity_date(self) -> datetime.datetime:
        return self._invalidity_date

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class PrecertificateSignedCertificateTimestamps(ExtensionType):
    oid = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS

    def __init__(
        self,
        signed_certificate_timestamps: typing.Iterable[
            SignedCertificateTimestamp
        ],
    ) -> None:
        signed_certificate_timestamps = list(signed_certificate_timestamps)
        if not all(
            isinstance(sct, SignedCertificateTimestamp)
            for sct in signed_certificate_timestamps
        ):
            raise TypeError(
                "Every item in the signed_certificate_timestamps list must be "
                "a SignedCertificateTimestamp"
            )
        self._signed_certificate_timestamps = signed_certificate_timestamps

    __len__, __iter__, __getitem__ = _make_sequence_methods(
        "_signed_certificate_timestamps"
    )

    def __repr__(self) -> str:
        return "<PrecertificateSignedCertificateTimestamps({})>".format(
            list(self)
        )

    def __hash__(self) -> int:
        return hash(tuple(self._signed_certificate_timestamps))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PrecertificateSignedCertificateTimestamps):
            return NotImplemented

        return (
            self._signed_certificate_timestamps
            == other._signed_certificate_timestamps
        )

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class SignedCertificateTimestamps(ExtensionType):
    oid = ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS

    def __init__(
        self,
        signed_certificate_timestamps: typing.Iterable[
            SignedCertificateTimestamp
        ],
    ) -> None:
        signed_certificate_timestamps = list(signed_certificate_timestamps)
        if not all(
            isinstance(sct, SignedCertificateTimestamp)
            for sct in signed_certificate_timestamps
        ):
            raise TypeError(
                "Every item in the signed_certificate_timestamps list must be "
                "a SignedCertificateTimestamp"
            )
        self._signed_certificate_timestamps = signed_certificate_timestamps

    __len__, __iter__, __getitem__ = _make_sequence_methods(
        "_signed_certificate_timestamps"
    )

    def __repr__(self) -> str:
        return "<SignedCertificateTimestamps({})>".format(list(self))

    def __hash__(self) -> int:
        return hash(tuple(self._signed_certificate_timestamps))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignedCertificateTimestamps):
            return NotImplemented

        return (
            self._signed_certificate_timestamps
            == other._signed_certificate_timestamps
        )

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class OCSPNonce(ExtensionType):
    oid = OCSPExtensionOID.NONCE

    def __init__(self, nonce: bytes) -> None:
        if not isinstance(nonce, bytes):
            raise TypeError("nonce must be bytes")

        self._nonce = nonce

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OCSPNonce):
            return NotImplemented

        return self.nonce == other.nonce

    def __hash__(self) -> int:
        return hash(self.nonce)

    def __repr__(self) -> str:
        return "<OCSPNonce(nonce={0.nonce!r})>".format(self)

    @property
    def nonce(self) -> bytes:
        return self._nonce

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class IssuingDistributionPoint(ExtensionType):
    oid = ExtensionOID.ISSUING_DISTRIBUTION_POINT

    def __init__(
        self,
        full_name: typing.Optional[typing.Iterable[GeneralName]],
        relative_name: typing.Optional[RelativeDistinguishedName],
        only_contains_user_certs: bool,
        only_contains_ca_certs: bool,
        only_some_reasons: typing.Optional[typing.FrozenSet[ReasonFlags]],
        indirect_crl: bool,
        only_contains_attribute_certs: bool,
    ) -> None:
        if full_name is not None:
            full_name = list(full_name)

        if only_some_reasons and (
            not isinstance(only_some_reasons, frozenset)
            or not all(isinstance(x, ReasonFlags) for x in only_some_reasons)
        ):
            raise TypeError(
                "only_some_reasons must be None or frozenset of ReasonFlags"
            )

        if only_some_reasons and (
            ReasonFlags.unspecified in only_some_reasons
            or ReasonFlags.remove_from_crl in only_some_reasons
        ):
            raise ValueError(
                "unspecified and remove_from_crl are not valid reasons in an "
                "IssuingDistributionPoint"
            )

        if not (
            isinstance(only_contains_user_certs, bool)
            and isinstance(only_contains_ca_certs, bool)
            and isinstance(indirect_crl, bool)
            and isinstance(only_contains_attribute_certs, bool)
        ):
            raise TypeError(
                "only_contains_user_certs, only_contains_ca_certs, "
                "indirect_crl and only_contains_attribute_certs "
                "must all be boolean."
            )

        crl_constraints = [
            only_contains_user_certs,
            only_contains_ca_certs,
            indirect_crl,
            only_contains_attribute_certs,
        ]

        if len([x for x in crl_constraints if x]) > 1:
            raise ValueError(
                "Only one of the following can be set to True: "
                "only_contains_user_certs, only_contains_ca_certs, "
                "indirect_crl, only_contains_attribute_certs"
            )

        if not any(
            [
                only_contains_user_certs,
                only_contains_ca_certs,
                indirect_crl,
                only_contains_attribute_certs,
                full_name,
                relative_name,
                only_some_reasons,
            ]
        ):
            raise ValueError(
                "Cannot create empty extension: "
                "if only_contains_user_certs, only_contains_ca_certs, "
                "indirect_crl, and only_contains_attribute_certs are all False"
                ", then either full_name, relative_name, or only_some_reasons "
                "must have a value."
            )

        self._only_contains_user_certs = only_contains_user_certs
        self._only_contains_ca_certs = only_contains_ca_certs
        self._indirect_crl = indirect_crl
        self._only_contains_attribute_certs = only_contains_attribute_certs
        self._only_some_reasons = only_some_reasons
        self._full_name = full_name
        self._relative_name = relative_name

    def __repr__(self) -> str:
        return (
            "<IssuingDistributionPoint(full_name={0.full_name}, "
            "relative_name={0.relative_name}, "
            "only_contains_user_certs={0.only_contains_user_certs}, "
            "only_contains_ca_certs={0.only_contains_ca_certs}, "
            "only_some_reasons={0.only_some_reasons}, "
            "indirect_crl={0.indirect_crl}, "
            "only_contains_attribute_certs="
            "{0.only_contains_attribute_certs})>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IssuingDistributionPoint):
            return NotImplemented

        return (
            self.full_name == other.full_name
            and self.relative_name == other.relative_name
            and self.only_contains_user_certs == other.only_contains_user_certs
            and self.only_contains_ca_certs == other.only_contains_ca_certs
            and self.only_some_reasons == other.only_some_reasons
            and self.indirect_crl == other.indirect_crl
            and self.only_contains_attribute_certs
            == other.only_contains_attribute_certs
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.full_name,
                self.relative_name,
                self.only_contains_user_certs,
                self.only_contains_ca_certs,
                self.only_some_reasons,
                self.indirect_crl,
                self.only_contains_attribute_certs,
            )
        )

    @property
    def full_name(self) -> typing.Optional[typing.List[GeneralName]]:
        return self._full_name

    @property
    def relative_name(self) -> typing.Optional[RelativeDistinguishedName]:
        return self._relative_name

    @property
    def only_contains_user_certs(self) -> bool:
        return self._only_contains_user_certs

    @property
    def only_contains_ca_certs(self) -> bool:
        return self._only_contains_ca_certs

    @property
    def only_some_reasons(
        self,
    ) -> typing.Optional[typing.FrozenSet[ReasonFlags]]:
        return self._only_some_reasons

    @property
    def indirect_crl(self) -> bool:
        return self._indirect_crl

    @property
    def only_contains_attribute_certs(self) -> bool:
        return self._only_contains_attribute_certs

    def public_bytes(self) -> bytes:
        return rust_x509.encode_extension_value(self)


class UnrecognizedExtension(ExtensionType):
    def __init__(self, oid: ObjectIdentifier, value: bytes) -> None:
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError("oid must be an ObjectIdentifier")
        self._oid = oid
        self._value = value

    @property
    def oid(self) -> ObjectIdentifier:  # type: ignore[override]
        return self._oid

    @property
    def value(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return (
            "<UnrecognizedExtension(oid={0.oid}, "
            "value={0.value!r})>".format(self)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnrecognizedExtension):
            return NotImplemented

        return self.oid == other.oid and self.value == other.value

    def __hash__(self) -> int:
        return hash((self.oid, self.value))

    def public_bytes(self) -> bytes:
        return self.value