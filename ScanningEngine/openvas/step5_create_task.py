from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree
import time

# ===== CONFIG =====
USERNAME = "admin"
PASSWORD = "StrongPassword123"
GVM_SOCKET = "/run/gvmd/gvmd.sock"

# From previous steps
TARGET_ID = "b0a2e9a6-a9ca-4a54-8bc6-f1d85b8c874d"
CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"


def get_scanner_id(gmp):
    response = gmp.get_scanners()
    tree = etree.fromstring(response.encode())

    for scanner in tree.xpath("//scanner"):
        if scanner.find("type").text == "2":  # OpenVAS scanner
            return scanner.get("id")

    raise RuntimeError("OpenVAS scanner not found")


def create_task():
    connection = UnixSocketConnection(path=GVM_SOCKET)

    with Gmp(connection=connection) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        scanner_id = get_scanner_id(gmp)

        task_name = f"Auto-Scan-{int(time.time())}"

        response = gmp.create_task(
            name=task_name,
            config_id=CONFIG_ID,
            target_id=TARGET_ID,
            scanner_id=scanner_id,
        )

        tree = etree.fromstring(response.encode())
        status = tree.get("status")

        if status in ["201", "200"]:
            task_id = tree.get("id")
            print("✓ Scan task created successfully")
            print(f"Task Name: {task_name}")
            print(f"Task ID: {task_id}")
            print("\n=== STEP-5 COMPLETE ===")
            return task_id
        else:
            raise RuntimeError(tree.get("status_text"))


if __name__ == "__main__":
    create_task()
