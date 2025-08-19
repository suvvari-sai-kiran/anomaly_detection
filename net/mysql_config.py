import os
from dotenv import load_dotenv
load_dotenv()

def get_db_config():
    return {
        "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
        "user": os.getenv("MYSQL_USER", "netmon2025_user"),
        "password": os.getenv("MYSQL_PASS", "SAIKIRAN"),
        "database": os.getenv("MYSQL_DB", "netmon2025_db"),
    }
