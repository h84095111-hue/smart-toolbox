from pathlib import Path
APP_DIR = Path.home() / '.smart-intel'
DATA_DIR = APP_DIR / 'data'
for p in (APP_DIR, DATA_DIR): p.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / 'smart-intel.sqlite3'
USER_AGENT = 'SmartIntel-OSINT/1.0 (public research client)'
REQUEST_TIMEOUT = 12
MAX_PAGE_BYTES = 1_500_000
