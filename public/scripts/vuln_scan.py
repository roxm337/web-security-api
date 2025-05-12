import sys
import json
import requests
import subprocess

def scan(url):
    results = {
        "sql_injection_test": False,
        "xss_test": False,
        "exposed_env": False,
        "directory_listing": False,
        "admin_panel_exposed": False,
        "cms_info": None,
        "vulnerable_components": [],
        "cve_lookup": []
    }

    try:
        # Basic Vuln Checks
        sqli_url = url + "?id=1' OR '1'='1"
        if "SQL" in requests.get(sqli_url, timeout=5).text:
            results["sql_injection_test"] = True

        xss_url = url + "?q=<script>alert(1)</script>"
        if "<script>alert(1)</script>" in requests.get(xss_url, timeout=5).text:
            results["xss_test"] = True

        if "APP_KEY=" in requests.get(url.rstrip('/') + "/.env", timeout=5).text:
            results["exposed_env"] = True

        if "Index of /uploads" in requests.get(url.rstrip('/') + "/uploads/", timeout=5).text:
            results["directory_listing"] = True

        # Admin Panel Exposure Check
        for path in ["/admin", "/admin/login", "/cpanel", "/backend", "/dashboard"]:
            r = requests.get(url.rstrip('/') + path, timeout=5)
            if r.status_code == 200 and "login" in r.text.lower():
                results["admin_panel_exposed"] = True
                break

        # Run WhatWeb for CMS detection
        ww = subprocess.run(["whatweb", "-q", "--log-json=-", url], capture_output=True, text=True)
        if ww.stdout:
            cms_info = json.loads(ww.stdout)[0]
            results["cms_info"] = cms_info.get("plugins", {})

            # CVE lookup from server/cms name
            server_info = cms_info.get("plugins", {}).get("Apache", {})
            if server_info:
                version = server_info.get("string", "")
                results["cve_lookup"].append(f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={version}")

        # Optional: Integrate nuclei scan
        nuclei_cmd = ["nuclei", "-u", url, "-silent", "-json"]
        nuclei_scan = subprocess.run(nuclei_cmd, capture_output=True, text=True)
        results["vulnerable_components"] = [json.loads(line) for line in nuclei_scan.stdout.splitlines()]

    except Exception as e:
        results["error"] = str(e)

    print(json.dumps(results))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No URL provided"}))
        sys.exit(1)
    scan(sys.argv[1])
