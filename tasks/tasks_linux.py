import os
from datetime import datetime

import pandas as pd
from celery import shared_task
from fabric import Connection

from .common import _parse_certificate


@shared_task
def scan_certificates_linux(host, user, password):
    try:
        conn = Connection(host=host, user=user, connect_kwargs={"password": password})

        command = """sudo find / -type f \\( \
                  -iname \"*.crt\" -o -iname \"*.cer\" -o -iname \"*.pem\" -o -iname \"*.der\" -o \
                    -iname \"*.p7b\" -o -iname \"*.p7c\" -o -iname \"*.pfx\" -o -iname \"*.p12\" \
                    \) \
                    -not -path \"/proc/*\" \
                    -not -path \"/sys/*\" \
                    -not -path \"/dev/*\" \
                    -not -path \"/run/*\" \
                    2>/dev/null
                    """

        result = conn.sudo(command, hide=True)
        files = result.stdout.strip().split("\n")

        certificates = []
        for file_path in files:
            if file_path.strip():
                try:
                    # Get file content
                    cat_result = conn.sudo(f"cat '{file_path}'", hide=True)
                    content = cat_result.stdout.encode()
                    cert = _parse_certificate(content)
                    if cert:
                        certificates.append(
                            {
                                "file_path": file_path,
                                "subject": cert.subject,
                                "issuer": cert.issuer,
                                "not_valid_before": cert.not_valid_before.isoformat(),
                                "not_valid_after": cert.not_valid_after.isoformat(),
                                "serial_number": cert.serial_number,
                                "signature_algorithm": cert.signature_algorithm,
                            }
                        )
                except Exception as e:
                    pass  # Skip files that can't be read or parsed

        # Save to Excel file
        if certificates:
            df = pd.DataFrame(certificates)
            output_dir = "certificate_reports"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(
                output_dir, f"certificates_linux_{host}_{timestamp}.xlsx"
            )
            df.to_excel(filename, index=False, engine="openpyxl")
            return {"status": "success", "file": filename, "count": len(certificates)}
        else:
            return {"status": "no_certificates_found"}
    except Exception as e:
        return {"error": str(e)}
