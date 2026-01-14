# KeyWatch2

A Flask application to scan and parse certificates on remote Linux machines using Fabric and cryptography.

## Features

- Scans remote Linux machines for certificate files (.crt, .cer, .pem, .der, .p7b, .p7c, .pfx, .p12)
- Parses certificate details using cryptography library
- Extracts subject, issuer, validity dates, serial number, and signature algorithm
- Web-based interface for easy use

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Ensure you have SSH key-based access to the remote machine.

3. Run the application:
   ```
   python app.py
   ```

4. Open your browser to `http://localhost:5000`

5. Enter the remote host details and scan.

## Requirements

- Python 3.x
- SSH access to remote machine with key-based authentication
- Sudo access on remote machine for finding and reading certificate files