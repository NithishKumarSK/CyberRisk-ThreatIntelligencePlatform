from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from lxml import etree

USERNAME = "admin"
PASSWORD = "StrongPassword123"
GVM_SOCKET = "/run/gvmd/gvmd.sock"


def get_scan_config_id(gmp):
    response = gmp.get_scan_configs()
    tree = etree.fromstring(response.encode("utf-8"))

    configs = tree.xpath("//config")
    if not configs:
        raise RuntimeError("No scan configurations found")

    print("\nAvailable Scan Configurations:")
    for cfg in configs:
        print(f" - {cfg.find('name').text}")

    # Prefer Full and fast
    for cfg in configs:
        if "Full and fast" in cfg.find("name").text:
            return cfg.get("id"), cfg.find("name").text

    # Fallback
    return configs[0].get("id"), configs[0].find("name").text


def main():
    connection = UnixSocketConnection(path=GVM_SOCKET)

    with Gmp(connection=connection) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        config_id, config_name = get_scan_config_id(gmp)

        print("\n✓ Scan Configuration Selected")
        print(f"Name: {config_name}")
        print(f"Config ID: {config_id}")
        print("\n=== STEP-4 COMPLETE ===")


if __name__ == "__main__":
    main()
