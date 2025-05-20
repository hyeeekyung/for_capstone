import subprocess
import os

def run_nmap(ip_address: str) -> dict:
    command = [
        "sudo", "/usr/bin/nmap", "-sV", "-O",
        "--script", "/usr/share/nmap/scripts/vulners.nse",
        ip_address
    ]

    # 환경 변수 보강 (Celery 환경 대응)
    env = os.environ.copy()
    env["HOME"] = "/home/skyroute"
    env["PATH"] += ":/usr/bin:/usr/sbin:/usr/local/bin"

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        return {
            "status": "success",
            "command": ' '.join(command),
            "output": result.stdout
        }
    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "command": ' '.join(command),
            "output": e.output
        }
