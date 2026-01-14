from collections import namedtuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend

Certificate = namedtuple(
    "Certificate",
    "subject, issuer, not_valid_before, not_valid_after, serial_number, signature_algorithm",
)


def _parse_certificate(content: bytes) -> Certificate | None:
    """
    Return the details from a certificate.
    Parses only DER or PEM encoded X.509 certificate.
    """
    content = content.strip()
    if (
        b"BEGIN CERTIFICATE REQUEST" in content
        or b"BEGIN NEW CERTIFICATE REQUEST" in content
    ):
        return None

    try:
        certificate = x509.load_pem_x509_certificate(content, default_backend())
    except ValueError:
        try:
            certificate = x509.load_der_x509_certificate(content, default_backend())
        except ValueError:
            return None

    return Certificate(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        not_valid_before=certificate.not_valid_before,
        not_valid_after=certificate.not_valid_after,
        serial_number=str(certificate.serial_number),
        signature_algorithm=certificate.signature_algorithm_oid._name,
    )