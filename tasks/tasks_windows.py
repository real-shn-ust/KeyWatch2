import base64
import json
import os
from datetime import datetime

import pandas as pd
import winrm
from celery import shared_task

try:
    from keywatch import mongo
except ImportError:
    import mongo
from .common import _parse_certificate


@shared_task(name="keywatch.tasks.tasks_windows.scan_certificates_windows", bind=True)
def scan_certificates_windows(self, host, user, password):
    try:
        # Create WinRM session
        session = winrm.Session(
            host,
            auth=(user, password),
        )

        # Get certificates from Windows Certificate Store using PowerShell
        ps_cmd = """
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
        """
        result = session.run_ps(ps_cmd)
        if result.status_code != 0:
            return {
                "error": f"Failed to query certificate store: {result.std_err.decode()}"
            }

        cert_data = json.loads(result.std_out.decode().strip())

        certificates = []
        total_files = len(cert_data)
        for count, item in enumerate(cert_data):
            try:
                content = base64.b64decode(item["RawData"])
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
                    self.update_state(
                        state="PROGRESS",
                        meta={"current": count + 1, "total": total_files},
                    )
            except Exception as e:
                pass  # Skip certificates that can't be parsed

        # Save to Excel file
        if certificates:
            data = {"host": host, "certificates": certificates}
            mongo.insert(data)
            return {"current": count, "total": total_files}
        else:
            return {"status": "no certificates found"}
    except Exception as e:
        return {"error": str(e)}
