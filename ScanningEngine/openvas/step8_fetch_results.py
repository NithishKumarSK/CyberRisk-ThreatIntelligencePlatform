from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree

GVM_SOCKET = "/run/gvmd/gvmd.sock"
USERNAME = "admin"
PASSWORD = "StrongPassword123"

# PUT YOUR REPORT ID HERE
REPORT_ID = "609f4621-185e-44e4-8868-d951ba73da9e"


def fetch_results():
    connection = UnixSocketConnection(path=GVM_SOCKET)

    with Gmp(connection=connection) as gmp:
        print("Authenticating with GVM...")
        gmp.authenticate(USERNAME, PASSWORD)
        print("✓ Authentication successful\n")

        print("Fetching report results...")
        response = gmp.get_report(
            REPORT_ID,
            details=True,
            ignore_pagination=True
        )

        tree = etree.fromstring(response.encode())

        results = tree.xpath("//result")

        severity_map = {
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Log": 0
        }

        for r in results:
            threat = r.findtext("threat")
            if threat in severity_map:
                severity_map[threat] += 1

        print("\n📊 Vulnerability Summary")
        print("========================")
        print(f"Total Findings: {len(results)}")
        print(f"High:   {severity_map['High']}")
        print(f"Medium: {severity_map['Medium']}")
        print(f"Low:    {severity_map['Low']}")
        print(f"Info:   {severity_map['Log']}")

        print("\n=== STEP-8 COMPLETE ===")


if __name__ == "__main__":
    fetch_results()
