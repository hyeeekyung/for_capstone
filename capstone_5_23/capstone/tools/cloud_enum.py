from flask import Flask
import os
import subprocess
from datetime import datetime

def run_cloud_enum(keyword):
    cloud_enum_path = os.path.expanduser("~/cloud-1/capstone/capstone/tools/cloud_enum/cloud_enum.py")
    command = ["python3", cloud_enum_path, "-k", keyword]

    start_time = datetime.now()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    log_dir = os.path.expanduser("~/cloud-1/capstone/capstone/logs")
    os.makedirs(log_dir, exist_ok=True)

    timestamp = start_time.strftime("%Y%m%d_%H%M%S_%f")
    log_path = os.path.join(log_dir, f"cloud_enum_{timestamp}.log")

    with open(log_path, "w", encoding="utf-8") as logfile:
        for line in iter(process.stdout.readline, ''):
            print("[LOG]", line.strip())
            logfile.write(line)
    process.stdout.close()
    process.wait()
    end_time = datetime.now()

    # ✅ 항상 output_file 포함
    return {
        "status": "success" if process.returncode == 0 else "error",
        "output_file": log_path,  # ← 항상 포함
        "command": " ".join(command),
        "start_time": start_time,
        "end_time": end_time
    }

