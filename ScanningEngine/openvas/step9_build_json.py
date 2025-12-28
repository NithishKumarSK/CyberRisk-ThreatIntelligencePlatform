import json
import time
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree

# Credentials
USERNAME = "admin"
PASSWORD = "StrongPassword123"
GVM_SOCKET = "/run/gvmd/gvmd.sock"

# Use report ID from Step-7
REPORT_ID = "609f4621-185e-44e4-8868-d951ba73da9e"


def severity_level(score):
    score = float(score)
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "Info"


def build_json():
    connection = UnixSocketConnection(path=GVM_SOCKET)

    with Gmp(connection=connection) as gmp:
        print("Authenticating with GVM...")
        gmp.authenticate(USERNAME, PASSWORD)
        print("✓ Authentication successful\n")

        print("Fetching report...")
        response = gmp.get_report(REPORT_ID, details=True)
        tree = etree.fromstring(response.encode())

        results = tree.xpath("//result")

        vulnerabilities = []

        for r in results:
            name = r.findtext("name")
            host = r.findtext("host")
            port = r.findtext("port")
            desc = r.findtext("description")
            score = r.findtext("severity") or "0.0"

            cve = None
            refs = r.find("nvt/refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    if ref.get("type") == "cve":
                        cve = ref.get("id")
                        break

            vulnerabilities.append({
                "name": name,
                "host": host,
                "port": port,
                "severity_score": float(score),
                "severity_level": severity_level(score),
                "cve": cve,
                "description": desc
            })

        output = {
            "scan_metadata": {
                "source": "OpenVAS",
                "report_id": REPORT_ID,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
            },
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

        with open("openvas_results.json", "w") as f:
            json.dump(output, f, indent=2)

        print("✓ JSON output created")
        print("File: openvas_results.json")
        print("\n=== STEP-9 COMPLETE ===")


if __name__ == "__main__":
    build_json()
