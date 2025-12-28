from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

# Credentials
USERNAME = "admin"
PASSWORD = "StrongPassword123"

# Socket
GVM_SOCKET = "/run/gvmd/gvmd.sock"

# Task ID from Step-5
TASK_ID = "63dae6a6-c756-4b8f-9384-0043fd2e4d80"

def start_scan():
    connection = UnixSocketConnection(path=GVM_SOCKET)

    with Gmp(connection=connection) as gmp:
        print("Authenticating with GVM...")
        gmp.authenticate(USERNAME, PASSWORD)
        print("✓ Authentication successful")

        print("Starting scan task...")
        response = gmp.start_task(TASK_ID)

        if 'status="202"' in response:
            print("✓ Scan started successfully")
        else:
            print("✗ Failed to start scan")
            print(response)

if __name__ == "__main__":
    start_scan()
    print("\n=== STEP-6 COMPLETE ===")
