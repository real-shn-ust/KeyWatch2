import os
import json
import base64
from collections import namedtuple

from celery import shared_task
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import winrm

from .common import _parse_certificate


@shared_task
def scan_certificates_windows(host, user, password):
    try:
        # Create WinRM session
        session = winrm.Session(
            f"http://{host}:5985/wsman",
            auth=(user, password),
            transport="ntlm"  # or 'kerberos' if needed
        )

        # Get certificates from Windows Certificate Store using PowerShell
        ps_cmd = '''
        $certificates = Get-ChildItem Cert:\\LocalMachine\\*, Cert:\\CurrentUser\\* -Recurse | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }
        $results = @()
        foreach ($cert in $certificates) {
            $results += [PSCustomObject]@{
                StorePath = $cert.PSParentPath
                Thumbprint = $cert.Thumbprint
                RawData = [Convert]::ToBase64String($cert.RawData)
            }
        }
        $results | ConvertTo-Json
        '''
        result = session.run_ps(ps_cmd)
        if result.status_code != 0:
            return {"error": f"Failed to query certificate store: {result.std_err.decode()}"}
        
        cert_data = json.loads(result.std_out.decode().strip())

        certificates = []
        for item in cert_data:
            try:
                content = base64.b64decode(item['RawData'])
                cert = _parse_certificate(content)
                if cert:
                    store_path = f"{item['StorePath']}\\{item['Thumbprint']}"
                    certificates.append(
                        {
                            "file_path": store_path,
                            "subject": cert.subject,
                            "issuer": cert.issuer,
                            "not_valid_before": cert.not_valid_before.isoformat(),
                            "not_valid_after": cert.not_valid_after.isoformat(),
                            "serial_number": cert.serial_number,
                            "signature_algorithm": cert.signature_algorithm,
                        }
                    )
            except Exception as e:
                pass  # Skip certificates that can't be parsed

        return {"certificates": certificates}
    except Exception as e:
        return {"error": str(e)}