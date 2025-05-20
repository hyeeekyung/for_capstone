# task_defs.py
from celery import Celery, Task
from resource_tool_map import RESOURCE_TOOL_MAP, classify_resource, custom_preprocess
from flask import Flask
from datetime import datetime
import requests
import re
import subprocess

# DB 생기면 그떄 연결                     
#from db_module import save_scan_result, extract_resources

# Celery 인스턴스 정의
celery = Celery('capstone_tasks', broker='redis://localhost:6379/0', backend='redis://localhost:6379/0')

def make_celery(app: Flask):
    celery.conf.update(app.config)
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    celery.Task = ContextTask
    return celery

class ContextTask(Task):
    def __call__(self, *args, **kwargs):
        from flask import current_app
        with current_app.app_context():
            return self.run(*args, **kwargs)
celery.Task = ContextTask

def build_meta(tool_id, raw):
    if tool_id == 1:  # nmap
        return {
            "tool_id": tool_id,
            "output": raw.get("output"),
            "command": raw.get("command")
        }
    elif tool_id == 2:  # cloud_enum
        return {
            "tool_id": tool_id,
            "output_file": raw.get("output_file"),
            "command": raw.get("command"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    elif tool_id == 3:  # amass
        return {
            "tool_id": tool_id,
            "output": raw.get("output"),
            "output_log": raw.get("output_log"),
            "command": raw.get("command"),
            "target_url": raw.get("target_url"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    elif tool_id == 4:  # s3scanner
        return {
            "tool_id": tool_id,
            "output": raw.get("output"),
            "command": raw.get("command"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    elif tool_id == 5:  # enumerate-iam
        return {
            "tool_id": tool_id,
            "output_file": raw.get("output_file"),
            "command": raw.get("command"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    elif tool_id == 6:  # nuclei
        return {
            "tool_id": tool_id,
            "output": raw.get("output"),
            "command": raw.get("command"),
            "target_url": raw.get("target_url"),
            "start_time": raw.get("start_time"),
            "end_time": raw.get("end_time")
        }
    else:
        return {"tool_id": tool_id, **raw}  # fallback


@celery.task(name='tasks.schedule_scan')
def schedule_scan(resource_type, value, scan_job_id, depth=0, max_depth=3):
    if depth > max_depth:
        return

    mappings = RESOURCE_TOOL_MAP.get(resource_type, [])
    for m in mappings:
        tool_id = m.get("tool_id", -1)

        # 필요한 input 인자 추출
        input_keys = m.get("input_args", [])
        input_values = []

    for arg in m.get("input_args", []):
        if isinstance(arg, dict) and "from" in arg:
            input_values.append(value)  # 그냥 현재 value
        elif isinstance(arg, dict) and "const" in arg:
            input_values.append(arg["const"])
        elif isinstance(arg, str):
            input_values.append(meta.get(arg))  # 이전 방식 호환
        else:
            input_values.append(None)

        if len(input_keys) == 1:
            input_values = [value]

        raw = m["tool"](*input_values)
        meta = build_meta(tool_id, raw)

        parser_args = []
        for arg in m.get("parser_args", []):
            if arg == "raw":
                parser_args.append(raw)
            elif arg == "meta":
                parser_args.append(meta)
            else:
                parser_args.append(meta.get(arg))

        print(f"[STEP {depth}] 실행 도구: {m['tool'].__name__}")
        print("==[DEBUG]==")
        print("Tool:", m['tool'].__name__)
        print("Args:", parser_args)
        print("Raw output keys:", list(raw.keys()))
        print("Meta:", meta)
        print("====================")

        parsed = m['parser'](*parser_args)
        print("[DEBUG] Parsed Result:", parsed)

        parsed_list = parsed if isinstance(parsed, tuple) else [parsed]
        for part in parsed_list:
            if not isinstance(part, dict):
                continue

            for nxt_key in m.get("next_resource", []):
                next_values = part.get(nxt_key)
                if not next_values:
                    continue
                if isinstance(next_values, str):
                    next_values = [next_values]

                for nxt_val in next_values:
                    tool_name = m["tool"].__name__

                    # S3Scanner의 object URL인 경우 → 파일 내용 긁어오기 
                    if tool_name == "run_s3scanner" and nxt_key == "object":
                        _, sensitive_files = parsed
                        for obj in sensitive_files:
                            fetch_s3_object.delay(obj, scan_job_id)
                        continue

                    nxt_val = custom_preprocess(nxt_val, nxt_key, tool_name)
                    nxt_type = classify_resource(nxt_val)

                    if nxt_type and depth < 1:
                        print(f"[DEBUG] 다음 스캔 → type: {nxt_type}, value: {nxt_val}")
                        schedule_scan.delay(nxt_type, nxt_val, scan_job_id, depth + 1, max_depth)


AWS_KEY_ID_RE = re.compile(r'AKIA[0-9A-Z]{16}')
AWS_SECRET_RE = re.compile(r'([A-Za-z0-9/+=]{40})')

@celery.task
def fetch_s3_object(obj_dict, parent_scan_id=None):
    """
    obj_dict 구조:
    {
      "object": "hello+4.txt",
      "object_size": "77 B",
      "object_type": ".txt",
      "target": "skyroute7"
      "url": "https://skyroute7.s3.ap-northeast-2.amazonaws.com/hello+4.txt"  ----> 오브젝트  url 추가
    }
    """
    url    = obj_dict.get("url")
    bucket = obj_dict.get("target")
    key    = obj_dict.get("object")

    try:
        resp = requests.get(url, timeout=15)
        content = resp.text if resp.status_code == 200 else ""
    except Exception:
        content = ""

    # 액세스 키/시크릿 키 패턴 매칭
    ids     = AWS_KEY_ID_RE.findall(content)
    secrets = AWS_SECRET_RE.findall(content)
    creds = []

    if ids and secrets:
        access_key = ids[0]
        secret_key = secrets[0]
        creds = [access_key, secret_key]

        # AWS CLI 프로파일 자동 등록
        profile = f"s3fetch-{parent_scan_id}"
        subprocess.run([
            "aws", "configure", "set", "aws_access_key_id", access_key
        ], check=False)
        subprocess.run([
            "aws", "configure", "set", "aws_secret_access_key", secret_key,
        ], check=False)
        subprocess.run([
            "aws", "configure", "set", "region", "ap-northeast-2",
        ], check=False)
        subprocess.run([
            "aws", "configure", "set", "output", "json"
        ], check=False)