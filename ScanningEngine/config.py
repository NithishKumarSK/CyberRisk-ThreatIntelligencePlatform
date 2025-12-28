from pathlib import Path

OPENVAS_HOST = '127.0.0.1'
OPENVAS_PORT = 9390
OPENVAS_USERNAME = 'admin'
OPENVAS_PASSWORD = 'Admin@1234'
SCAN_STATUS_CHECK_INTERVAL = 15
NMAP_PROFILE = '-sV -sC'

BASE_DIR = Path(__file__).parent
RESULTS_DIR = BASE_DIR / 'scan_results'
LOGS_DIR = BASE_DIR / 'logs'

for d in (RESULTS_DIR, LOGS_DIR):
    d.mkdir(exist_ok=True)

