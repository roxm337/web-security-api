# Web Security Scanner

This project is a web security scanner that performs various checks on a provided URL. It scans for:

- HTTP headers
- SSL/TLS certificate details
- Potential vulnerabilities using a Python script (`vuln_scan.py`)

It is built with **Laravel** (PHP) for the backend and **Python** for vulnerability scanning. The frontend can be built with **Flutter** (optional for mobile or web use).

## Features

- **HTTP Headers Scan**: Analyzes HTTP response headers and checks for security-related headers like `X-XSS-Protection`, `X-Content-Type-Options`, etc.
- **SSL/TLS Scan**: Checks the validity of the SSL certificate, including issuer, validity dates, etc.
- **Vulnerability Scan**: Executes a Python script to identify potential vulnerabilities like open ports, weak security protocols, etc.

## Technologies

- **Backend**: Laravel (PHP)
- **Frontend**: (Optional) Flutter
- **Vulnerability Scan**: Python

## Requirements

- PHP >= 7.4
- Laravel 8.x or above
- Python 3.x
- Composer (for managing PHP dependencies)
- Python packages for vulnerability scanning

## Installation and Setup

### Step 1: Clone the Repository

Clone the repository to your local machine:

```bash
git clone https://github.com/roxm337/web-security-scanner.git
cd web-security-scanner
```

Ensure Python Script (vuln_scan.py) is Located in the Correct Path:

Make sure that the vuln_scan.py script is placed in the scripts/ folder and is executable.

If necessary, provide execution permissions to the script:
```bash
chmod +x scripts/vuln_scan.py
```

### Test the API

To test the API, you can use Postman or cURL.
API Endpoint:

    POST /api/scan

Request Body (JSON):

```json
{
    "url": "https://example.com"
}
```
### Example Response:
```json
{
    "status": "online",
    "ssl": {
        "valid_from": "2024-01-01",
        "valid_to": "2025-01-01",
        "issuer": "Let's Encrypt"
    },
    "headers": {
        "security": "1; mode=block",
        "server": "nginx",
        "powered_by": "PHP/8.1.2"
    },
    "vulnerabilities": [
        { ... }
    ]
}
```

### Example Use Case
```bash
curl -X POST http://127.0.0.1:8000/api/scan -d "url=https://example.com" -H "Content-Type: application/json"
