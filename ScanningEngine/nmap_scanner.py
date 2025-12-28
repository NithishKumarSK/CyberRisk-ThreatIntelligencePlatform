import json
from datetime import datetime

import nmap
from config import RESULTS_DIR, NMAP_PROFILE
from logger import ScanLogger


class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.log = ScanLogger('nmap')

    def scan(self, target):
        self.log.info(f'Starting NMAP scan on {target}')
        try:
            self.scanner.scan(
                hosts=target,
                arguments=NMAP_PROFILE
            )

            results = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'command': self.scanner.command_line(),
                'hosts': {}
            }

            for host in self.scanner.all_hosts():
                host_data = {
                    'hostname': self.scanner[host].hostname(),
                    'state': self.scanner[host].state(),
                    'services': []
                }

                for proto in self.scanner[host].all_protocols():
                    for port in self.scanner[host][proto].keys():
                        svc = self.scanner[host][proto][port]
                        host_data['services'].append({
                            'port': port,
                            'protocol': proto,
                            'state': svc.get('state'),
                            'service': svc.get('name'),
                            'product': svc.get('product', ''),
                            'version': svc.get('version', '')
                        })

                results['hosts'][host] = host_data

            self.log.info(
                f'NMAP scan completed. Found {len(results["hosts"])} hosts'
            )
            return results

        except Exception as e:
            self.log.error(f'NMAP scan failed: {str(e)}')
            return None

    def save(self, results, filename):
        filepath = RESULTS_DIR / filename
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        self.log.info(f'Results saved to {filepath}')
        return filepath

