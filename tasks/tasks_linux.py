import os
from datetime import datetime

import pandas as pd
from celery import shared_task
from fabric import Connection

try:
    from keywatch import mongo
except ImportError:
    import mongo
from .common import _parse_certificate


@shared_task(name="keywatch.tasks.tasks_linux.scan_certificates_linux", bind=True)
def scan_certificates_linux(self, host, user, password):
    try:
        conn = Connection(host=host, user=user, connect_kwargs={"password": password})

        command = """sudo find / -type f \\( \
                    -iname \"*.crt\" -o -iname \"*.cer\" -o -iname \"*.pem\" -o -iname \"*.der\" \
                    \\) \
                    -not -path \"/proc/*\" \
                    -not -path \"/sys/*\" \
                    -not -path \"/dev/*\" \
                    -not -path \"/run/*\" \
                    2>/dev/null
                    """

        result = conn.sudo(command, hide=True)
        files = result.stdout.strip().split("\n")

        total_files = len(files)
        for count, file_path in enumerate(files):
            if file_path.strip():
                try:
                    cat_result = conn.sudo(f"cat '{file_path}'", hide=True)
                    content = cat_result.stdout.encode()
                    cert = _parse_certificate(content)
                    if cert:
                        self.update_state(
                            state="PROGRESS",
                            meta={"current": count + 1, "total": total_files},
                        )
                        data = {
                            "host": host,
                            "file_path": file_path,
                            "subject": cert.subject,
                            "issuer": cert.issuer,
                            "not_valid_before": cert.not_valid_before,
                            "not_valid_after": cert.not_valid_after,
                            "serial_number": cert.serial_number,
                            "signature_algorithm": cert.signature_algorithm,
                        }
                        mongo.insert(data)
                except Exception as e:
                    return {"error": str(e)}

        return {"current": count, "total": total_files}
    except Exception as e:
        return {"error": str(e)}
