from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv208.entities.targets import AliveTest
from lxml import etree

USERNAME = "admin"
PASSWORD = "StrongPassword123"
GVM_SOCKET = "/run/gvmd/gvmd.sock"

alive_hosts = ["45.33.32.156"]


def get_port_list_id(gmp):
    response = gmp.get_port_lists()
    tree = etree.fromstring(response.encode())
    return tree.xpath("//port_list/@id")[0]


def get_or_create_target(gmp, hosts):
    target_name = f"Target-{hosts.replace('.', '-')}"
    
    # Check existing targets
    response = gmp.get_targets()
    tree = etree.fromstring(response.encode())

    for target in tree.xpath("//target"):
        if target.find("name").text == target_name:
            print(f"✓ Existing target found")
            return target.get("id")

    print("✓ Creating new target...")
    port_list_id = get_port_list_id(gmp)

    response = gmp.create_target(
        name=target_name,
        hosts=hosts,                 # STRING, NOT LIST
        port_list_id=port_list_id,
        alive_test=AliveTest.CONSIDER_ALIVE
    )

    tree = etree.fromstring(response.encode())
    return tree.get("id")


def main():
    host_string = ",".join(alive_hosts)

    connection = UnixSocketConnection(path=GVM_SOCKET)
    with Gmp(connection=connection) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)
        target_id = get_or_create_target(gmp, host_string)

        print("\n=== STEP-3 COMPLETE ===")
        print("Target ID:", target_id)


if __name__ == "__main__":
    main()
