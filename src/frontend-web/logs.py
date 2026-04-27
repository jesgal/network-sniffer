import os
import subprocess
import re
from datetime import datetime

LOG_DIR = "/var/log/network-sniffer"
MAX_LINES = 10000


# ---------------------------------------------------------
# Obtener logs principales (*.log)
# ---------------------------------------------------------
def get_main_logs():
    try:
        logs = []
        for f in os.listdir(LOG_DIR):
            full_path = os.path.join(LOG_DIR, f)
            if f.endswith(".log") and os.path.isfile(full_path):
                logs.append(f)

        logs.sort(key=lambda x: os.path.getmtime(os.path.join(LOG_DIR, x)), reverse=True)
        return logs

    except Exception as e:
        print(f"Error accediendo a LOG_DIR: {e}")
        return []


# ---------------------------------------------------------
# Obtener logs rotados relacionados
# ---------------------------------------------------------
def get_related_logs(base_log):
    prefix = base_log.replace(".log", "")
    main_file = base_log
    rotated = []

    for f in os.listdir(LOG_DIR):
        if f.startswith(prefix + ".log") and f != main_file:
            rotated.append(f)

    rotated.sort(reverse=True)
    return [main_file] + rotated


# ---------------------------------------------------------
# Lectura de archivos normales
# ---------------------------------------------------------
def read_file_reverse(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.readlines()[::-1]
    except:
        return []


# ---------------------------------------------------------
# Lectura de archivos .gz
# ---------------------------------------------------------
def read_gz_reverse(path):
    try:
        result = subprocess.run(
            ["zcat", path],
            capture_output=True,
            text=True,
            check=False
        )
        return result.stdout.splitlines()[::-1]
    except:
        return []

def parse_timestamp(line):
    # Extraer lo que está entre corchetes
    match = re.match(r"\[(.*?)\]", line)
    
    if not match:
        return datetime.min  # si no hay timestamp, lo mandamos al principio
    
    ts = match.group(1)

    # Formato: 21-03-2026 10:36:51.610+01:00
    return datetime.strptime(ts, "%d-%m-%Y %H:%M:%S.%f%z")