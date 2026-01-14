from flask import Flask, request, jsonify
from fabric import Connection
import io
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from collections import namedtuple

app = Flask(__name__)

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

@app.route('/scan', methods=['GET'])
def scan():
    host = request.args.get('host')
    user = request.args.get('user')
    password = request.args.get('password')
    
    if not host or not user or not password:
        return jsonify({"error": "Missing required parameters: host, user, password"}), 400
    
    try:
        conn = Connection(host=host, user=user, connect_kwargs={'password': password})
        
        find_cmd = (
            "sudo find / -type f "
            "( -iname '*.crt' -o -iname '*.cer' -o -iname '*.pem' "
            "-o -iname '*.der' -o -iname '*.p7b' -o -iname '*.p7c' "
            "-o -iname '*.pfx' -o -iname '*.p12' ) "
            "-not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -not -path '/run/*'"
        )
        result = conn.sudo(find_cmd, hide=True)
        files = result.stdout.strip().split('\n')
        
        certificates = []
        for file_path in files:
            if file_path.strip():
                try:
                    # Get file content
                    cat_result = conn.sudo(f"cat '{file_path}'", hide=True)
                    content = cat_result.stdout.encode()
                    cert = _parse_certificate(content)
                    if cert:
                        certificates.append({
                            "file_path": file_path,
                            "subject": cert.subject,
                            "issuer": cert.issuer,
                            "not_valid_before": cert.not_valid_before.isoformat(),
                            "not_valid_after": cert.not_valid_after.isoformat(),
                            "serial_number": cert.serial_number,
                            "signature_algorithm": cert.signature_algorithm
                        })
                except Exception as e:
                    pass  # Skip files that can't be read or parsed
        
        return jsonify({"certificates": certificates})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)