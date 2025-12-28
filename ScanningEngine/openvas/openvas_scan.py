from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv208.entities.targets import AliveTest
from lxml import etree
import ipaddress
import time

# GVM Credentials
USERNAME = "admin"
PASSWORD = "StrongPassword123"

# GVMD Unix Socket (WSL / Ubuntu)
GVM_SOCKET = "/run/gvmd/gvmd.sock"


def validate_ip(ip):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_any_port_list_id(gmp):
    """Fetch any available port list ID from GVM."""
    response = gmp.get_port_lists()
    tree = etree.fromstring(response.encode("utf-8"))
    port_lists = tree.xpath("//port_list/@id")
    if not port_lists:
        raise RuntimeError("No port lists found in GVM.")
    return port_lists[0]


def get_scan_config_id(gmp):
    """Get a scan configuration ID, prioritizing Discovery for speed."""
    print("Fetching scan configurations...")
    response = gmp.get_scan_configs()
    tree = etree.fromstring(response.encode("utf-8"))
    configs = tree.xpath("//config")
    
    if not configs:
        raise RuntimeError("No scan configs found.")
    
    # WE ARE CHANGING THIS TO "Discovery" FOR A FAST RESULT
    for config in configs:
        name = config.find("name").text
        if "Discovery" in name:
            config_id = config.get("id")
            print(f"\n✓ Using FAST config: {name}")
            return config_id
            
    # Fallback to whatever is available
    config_id = configs[0].get("id")
    print(f"\n✓ Using: {configs[0].find('name').text}")
    return config_id


def get_scanner_id(gmp):
    """Get the OpenVAS scanner ID."""
    response = gmp.get_scanners()
    tree = etree.fromstring(response.encode("utf-8"))
    scanners = tree.xpath("//scanner")
    
    if not scanners:
        raise RuntimeError("No scanners found")
    
    for scanner in scanners:
        name = scanner.find("name").text
        scanner_type = scanner.find("type").text
        if scanner_type == "2":  # OpenVAS Scanner type
            scanner_id = scanner.get("id")
            print(f"✓ Using scanner: {name} (ID: {scanner_id})")
            return scanner_id
    
    # Return first scanner
    scanner_id = scanners[0].get("id")
    name = scanners[0].find("name").text
    print(f"✓ Using scanner: {name} (ID: {scanner_id})")
    return scanner_id


def get_or_create_target(gmp, alive_hosts):
    """Get existing target or create new one."""
    if not alive_hosts:
        raise ValueError("No alive hosts provided")
    
    # Validate hosts
    valid_hosts = [host for host in alive_hosts if validate_ip(host)]
    if not valid_hosts:
        raise ValueError("No valid hosts to scan")
    
    target_name = f"Target-{valid_hosts[0].replace('.', '-')}"
    
    # Check if target already exists
    print(f"Checking for existing target '{target_name}'...")
    response = gmp.get_targets()
    tree = etree.fromstring(response.encode("utf-8"))
    
    for target in tree.xpath("//target"):
        name = target.find("name").text
        if name == target_name:
            target_id = target.get("id")
            print(f"✓ Using existing target: {target_id}")
            return target_id
    
    # Create new target
    print(f"Creating new target with {len(valid_hosts)} host(s)...")
    port_list_id = get_any_port_list_id(gmp)
    
    response = gmp.create_target(
        name=target_name,
        hosts=valid_hosts,
        port_list_id=port_list_id,
        alive_test=AliveTest.CONSIDER_ALIVE
    )
    
    tree = etree.fromstring(response.encode("utf-8"))
    status = tree.get("status")
    
    if status in ["201", "200"]:
        target_id = tree.get("id")
        print(f"✓ Target created: {target_id}")
        return target_id
    else:
        raise RuntimeError(f"Target creation failed: {tree.get('status_text')}")


def create_and_start_scan(gmp, target_id):
    """Create and start a scan task."""
    print("\nSetting up scan task...")
    
    # Get required IDs
    config_id = get_scan_config_id(gmp)
    scanner_id = get_scanner_id(gmp)
    
    # Create task
    print("\nCreating scan task...")
    response = gmp.create_task(
        name=f"Scan-Task-{int(time.time())}",
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id
    )
    
    tree = etree.fromstring(response.encode("utf-8"))
    status = tree.get("status")
    
    if status not in ["201", "200"]:
        raise RuntimeError(f"Task creation failed: {tree.get('status_text')}")
    
    task_id = tree.get("id")
    print(f"✓ Task created: {task_id}")
    
    # Start the task
    print("Starting scan...")
    response = gmp.start_task(task_id)
    tree = etree.fromstring(response.encode("utf-8"))
    
    if tree.get("status") == "202":
        report_id = tree.find(".//report_id").text
        print(f"✓ Scan started successfully!")
        print(f"  Task ID: {task_id}")
        print(f"  Report ID: {report_id}")
        return task_id, report_id
    else:
        raise RuntimeError(f"Failed to start scan: {tree.get('status_text')}")


def check_scan_status(gmp, task_id):
    """Check the status of a running scan."""
    response = gmp.get_task(task_id)
    tree = etree.fromstring(response.encode("utf-8"))
    
    task = tree.find(".//task")
    status = task.find("status").text
    progress = task.find("progress").text
    
    return status, int(progress) if progress != "-1" else 0


def main():
    print("=" * 70)
    print("OpenVAS Complete Scanning Workflow")
    print("=" * 70)
    
    # Target host
    alive_hosts = ["45.33.32.156"]
    print(f"\nTarget hosts: {alive_hosts}\n")
    
    connection = UnixSocketConnection(path=GVM_SOCKET)
    
    try:
        with Gmp(connection=connection) as gmp:
            # Authenticate
            print("Authenticating with GVM...")
            gmp.authenticate(USERNAME, PASSWORD)
            print("✓ Authentication successful\n")
            
            # Get or create target
            target_id = get_or_create_target(gmp, alive_hosts)
            
            # Create and start scan
            task_id, report_id = create_and_start_scan(gmp, target_id)
            
            # Monitor scan progress
            print("\n" + "=" * 70)
            print("Monitoring scan progress...")
            print("=" * 70)
            
            last_progress = -1
            while True:
                status, progress = check_scan_status(gmp, task_id)
                
                if progress != last_progress:
                    print(f"\rStatus: {status:15} | Progress: {progress:3}%", end="", flush=True)
                    last_progress = progress
                
                if status in ["Done", "Stopped", "Interrupted"]:
                    print()
                    break
                
                time.sleep(5)
            
            print("\n" + "=" * 70)
            print(f"✓ Scan completed with status: {status}")
            print(f"  Task ID: {task_id}")
            print(f"  Report ID: {report_id}")
            print("=" * 70)
            
            # Get results summary
            print("\nFetching scan results...")
            response = gmp.get_report(report_id)
            tree = etree.fromstring(response.encode("utf-8"))
            
            # Count vulnerabilities by severity
            results = tree.xpath("//result")
            high = len([r for r in results if r.find("threat").text == "High"])
            medium = len([r for r in results if r.find("threat").text == "Medium"])
            low = len([r for r in results if r.find("threat").text == "Low"])
            
            print(f"\n📊 Results Summary:")
            print(f"  🔴 High:   {high}")
            print(f"  🟡 Medium: {medium}")
            print(f"  🔵 Low:    {low}")
            print(f"  📝 Total:  {len(results)}")
            
    except Exception as e:
        print(f"\n✗ Error: {e}")


if __name__ == "__main__":
    main()