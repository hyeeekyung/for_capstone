import os
import subprocess
from datetime import datetime

def run_cloud_enum(keyword: str) -> dict:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    home_dir = os.path.abspath(os.path.join(current_dir, '../../..'))
    cloud_enum_file_path = os.path.join(home_dir, 'cloud-1', 'capstone', 'capstone', 'tools', 'cloud_enum', 'cloud_enum.py')

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file_path = os.path.join(home_dir, 'cloud-1', 'cloud_enum', f'cloud_enum_output_{timestamp}.txt')

    command = ["python3", cloud_enum_file_path, "-k", keyword]
    start_time = datetime.now()

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        end_time = datetime.now()
    except Exception as e:
        return {
            "tool": "cloud_enum",
            "output": str(e),
            "status": "error",
            "command": ' '.join(command),
            "start_time": start_time,
            "end_time": datetime.now()
        }

    if result.returncode == 0 or result.stdout.strip():
        try:
            os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.write(result.stdout)
        except Exception as e:
            return {
                "tool": "cloud_enum",
                "output": f"[파일 저장 오류] {e}",
                "status": "error",
                "command": ' '.join(command),
                "start_time": start_time,
                "end_time": end_time
            }

        return {
            "tool": "cloud_enum",
            "output_file": output_file_path,
            "command": ' '.join(command),
            "start_time": start_time,
            "end_time": end_time,
            "status": "success"
        }
    else:
        return {
            "tool": "cloud_enum",
            "output": result.stderr,
            "status": "error",
            "command": ' '.join(command),
            "start_time": start_time,
            "end_time": end_time
        }
