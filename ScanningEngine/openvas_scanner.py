import json
import time
from datetime import datetime

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp

from config import (
    OPENVAS_HOST,
    OPENVAS_PORT,
    OPENVAS_USERNAME,
    OPENVAS_PASSWORD,
    SCAN_STATUS_CHECK_INTERVAL,
    RESULTS_DIR,
)
from logger import ScanLogger


class OpenVASScanner:
    def __init__(self):
        self.log = ScanLogger('openvas')
        self.connection = None
        self.gmp = None

    def connect(self):
        try:
            self.log.info(
                f'Connecting to OpenVAS at {OPENVAS_HOST}:{OPENVAS_PORT}'
            )
            self.connection = TLSConnection(
                hostname=OPENVAS_HOST,
                port=OPENVAS_PORT
            )
            self.gmp = Gmp(connection=self.connection)
            self.gmp.connect()
            self.gmp.authenticate(
                OPENVAS_USERNAME,
                OPENVAS_PASSWORD
            )
            version = self.gmp.get_version().xpath(
                'version/text()'
            )[0]
            self.log.info(f'Connected to OpenVAS version {version}')
            return True

        except Exception as e:
            self.log.error(f'Connection failed: {str(e)}')
            return False

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            self.log.info('Disconnected from OpenVAS')

    def create_target(self, name, hosts):
        try:
            response = self.gmp.create_target(
                name=name,
                hosts=[hosts]
            )
            target_id = response.xpath('@id')[0]
            self.log.info(f'Target created with ID {target_id}')
            return target_id

        except Exception as e:
            self.log.error(f'Target creation failed: {str(e)}')
            return None

    def get_config_id(self):
        try:
            response = self.gmp.get_scan_configs()
            for config in response.xpath('config'):
                name = config.xpath('name/text()')[0]
                if 'full and fast' in name.lower():
                    config_id = config.xpath('@id')[0]
                    self.log.info(f'Using scan config: {name}')
                    return config_id
            return None

        except Exception as e:
            self.log.error(f'Get config failed: {str(e)}')
            return None

    def get_scanner_id(self):
        try:
            response = self.gmp.get_scanners()
            for scanner in response.xpath('scanner'):
                if scanner.xpath('type/text()')[0] == '2':
                    scanner_id = scanner.xpath('@id')[0]
                    scanner_name = scanner.xpath('name/text()')[0]
                    self.log.info(f'Using scanner: {scanner_name}')
                    return scanner_id
            return None

        except Exception as e:
            self.log.error(f'Get scanner failed: {str(e)}')
            return None

    def create_task(self, name, target_id, config_id, scanner_id):
        try:
            response = self.gmp.create_task(
                name=name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id
            )
            task_id = response.xpath('@id')[0]
            self.log.info(f'Task created with ID {task_id}')
            return task_id

        except Exception as e:
            self.log.error(f'Task creation failed: {str(e)}')
            return None

    def start_task(self, task_id):
        try:
            response = self.gmp.start_task(task_id)
            report_id = response.xpath('report_id/text()')[0]
            self.log.info(f'Task started with report ID {report_id}')
            return report_id

        except Exception as e:
            self.log.error(f'Task start failed: {str(e)}')
            return None

    def wait_for_completion(self, task_id):
        self.log.info('Waiting for scan to complete')
        while True:
            try:
                response = self.gmp.get_task(task_id)
                status = response.xpath(
                    'task/status/text()'
                )[0]
                progress = int(
                    response.xpath('task/progress/text()')[0]
                )
                self.log.info(
                    f'Status: {status} | Progress: {progress}%'
                )

                if status == 'Done':
                    self.log.info('Scan completed')
                    return True
                elif status in ['Stopped', 'Interrupted']:
                    self.log.error(f'Scan {status}')
                    return False

                time.sleep(SCAN_STATUS_CHECK_INTERVAL)

            except Exception as e:
                self.log.error(f'Status check failed: {str(e)}')
                return False

    def get_results(self, task_id):
        try:
            self.log.info('Retrieving scan results')

            response = self.gmp.get_task(task_id)
            report_id = response.xpath(
                'task/last_report/report/@id'
            )[0]
            report = self.gmp.get_report(
                report_id,
                details=True
            )

            vulnerabilities = []
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0,
            }

            for result in report.xpath('report/results/result'):
                severity = float(
                    result.xpath('severity/text()')[0]
                )

                if severity >= 9.0:
                    sev_level = 'critical'
                elif severity >= 7.0:
                    sev_level = 'high'
                elif severity >= 4.0:
                    sev_level = 'medium'
                elif severity > 0:
                    sev_level = 'low'
                else:
                    sev_level = 'info'

                severity_counts[sev_level] += 1

                vuln = {
                    'name': result.xpath('name/text()')[0],
                    'severity': severity,
                    'severity_level': sev_level,
                    'host': result.xpath('host/text()')[0],
                    'port': result.xpath('port/text()')[0],
                    'description': (
                        result.xpath('description/text()')[0]
                        if result.xpath('description/text()')
                        else ''
                    ),
                }
                vulnerabilities.append(vuln)

            vulnerabilities.sort(
                key=lambda x: x['severity'],
                reverse=True
            )

            results = {
                'timestamp': datetime.now().isoformat(),
                'task_id': task_id,
                'report_id': report_id,
                'total_vulnerabilities': len(vulnerabilities),
                'severity_distribution': severity_counts,
                'vulnerabilities': vulnerabilities,
            }

            self.log.info(
                f'Retrieved {len(vulnerabilities)} vulnerabilities'
            )
            return results

        except Exception as e:
            self.log.error(f'Get results failed: {str(e)}')
            return None

    def save(self, results, filename):
        filepath = RESULTS_DIR / filename
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        self.log.info(f'Results saved to {filepath}')
        return filepath

