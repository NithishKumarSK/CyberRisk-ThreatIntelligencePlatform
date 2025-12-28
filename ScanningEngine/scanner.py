from datetime import datetime

from logger import ScanLogger
from nmap_scanner import NmapScanner
from openvas_scanner import OpenVASScanner


class ScanningEngine:
    def __init__(self):
        self.log = ScanLogger('engine', 'scan_engine.log')
        self.nmap = NmapScanner()
        self.openvas = OpenVASScanner()

    def run(self, target):
        self.log.info(f'Starting scan on {target}')

        nmap_results = self.nmap.scan(target)
        if nmap_results:
            self.nmap.save(
                nmap_results,
                f'nmap_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            )

        if not self.openvas.connect():
            return

        try:
            scan_name = f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            target_id = self.openvas.create_target(scan_name, target)
            if not target_id:
                return

            config_id = self.openvas.get_config_id()
            if not config_id:
                return

            scanner_id = self.openvas.get_scanner_id()
            if not scanner_id:
                return

            task_id = self.openvas.create_task(
                scan_name, target_id, config_id, scanner_id
            )
            if not task_id:
                return

            report_id = self.openvas.start_task(task_id)
            if not report_id:
                return

            if not self.openvas.wait_for_completion(task_id):
                return

            openvas_results = self.openvas.get_results(task_id)
            if openvas_results:
                self.openvas.save(
                    openvas_results,
                    f'openvas_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
                )
                print(
                    f'\nScan Complete: '
                    f'{openvas_results["total_vulnerabilities"]} vulnerabilities found'
                )

        finally:
            self.openvas.disconnect()


def main():
    print('1. scanme.nmap.org\n2. 127.0.0.1\n3. Custom target')
    choice = input('Select (1/2/3): ').strip()

    if choice == '1':
        target = 'scanme.nmap.org'
    elif choice == '2':
        target = '127.0.0.1'
    elif choice == '3':
        target = input('Enter target: ').strip()
        if input('Have permission? (yes/no): ').lower() != 'yes':
            return
    else:
        return

    ScanningEngine().run(target)


if __name__ == '__main__':
    main()

