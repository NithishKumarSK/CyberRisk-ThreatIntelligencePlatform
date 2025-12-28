from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree
import time

USERNAME = "admin"
PASSWORD = "StrongPassword123"
SOCKET_PATH = "/run/gvmd/gvmd.sock"

TASK_ID = "63dae6a6-c756-4b8f-9384-0043fd2e4d80"


def monitor_scan():
    connection = UnixSocketConnection(path=SOCKET_PATH)

    with Gmp(connection=connection) as gmp:
        print("Authenticating with GVM...")
        gmp.authenticate(USERNAME, PASSWORD)
        print("✓ Authentication successful\n")

        print("Monitoring scan progress...\n")

        while True:
            response = gmp.get_task(TASK_ID)
            tree = etree.fromstring(response.encode())

            task = tree.find(".//task")
            status = task.findtext("status")
            progress = task.findtext("progress")

            print(f"Status: {status:12} | Progress: {progress}%")

            if status in ["Done", "Stopped", "Interrupted"]:
                report = task.find(".//report")
                report_id = report.get("id") if report is not None else None

                print("\n=== STEP-7 COMPLETE ===")
                print(f"Final Status: {status}")
                print(f"Report ID: {report_id}")
                return report_id

            time.sleep(5)


if __name__ == "__main__":
    monitor_scan()
