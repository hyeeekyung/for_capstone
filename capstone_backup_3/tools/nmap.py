import subprocess
import os

def run_nmap(ip_address: str) -> dict:
    command = [
        "sudo", "/usr/bin/nmap", "-sV", "-O",
        "--script", "/usr/share/nmap/scripts/vulners.nse",
        ip_address
    ]

    env = os.environ.copy()
    env["HOME"] = "/home/skyroute"
    env["PATH"] += ":/usr/share/nmap/scripts"

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
