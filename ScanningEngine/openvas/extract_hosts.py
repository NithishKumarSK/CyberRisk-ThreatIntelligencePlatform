import json
import os


def extract_alive_hosts(nmap_json_path):
    with open(nmap_json_path, "r") as file:
        data = json.load(file)

    hosts_data = data.get("hosts", {})

    alive_hosts = [
        ip
        for ip, details in hosts_data.items()
        if details.get("state") == "up"
    ]

    return alive_hosts


def get_latest_nmap_file(scan_results_dir):
    files = [
        f for f in os.listdir(scan_results_dir)
        if f.startswith("nmap_") and f.endswith(".json")
    ]
    files.sort()
    return os.path.join(scan_results_dir, files[-1]) if files else None


if __name__ == "__main__":
    scan_results_dir = os.path.join("..", "scan_results")
    latest_nmap_file = get_latest_nmap_file(scan_results_dir)

    if not latest_nmap_file:
        print("No Nmap scan files found.")
        exit(1)

    hosts = extract_alive_hosts(latest_nmap_file)
    print("Alive hosts:", hosts)
