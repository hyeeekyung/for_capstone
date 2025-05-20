import re
from collections import defaultdict

def extract_target_url(command):
    match = re.search(r"-u\s+(http[s]?://\S+)", command)
    return match.group(1) if match else None

def extract_core_logs(log_text):
    return "\n".join(
        line for line in log_text.splitlines()
        if line.startswith("[detect-dangling-s3")
    )

def infer_success(log_text):
    matches = re.findall(r"Matched:\s*(\d+)", log_text)
    if matches:
        final = int(matches[-1])
        return 1 if final == 2 else 0
    return 0

def extract_all_cname_records(log_text, base_domain):
    """
    CNAME\t<도메인> 형식 그대로 추출하고 리스트로 반환
    """
    pattern = re.search(rf"\[dns\]\s+\[info\]\s+{re.escape(base_domain)}\s+\[(.*?)\]", log_text)
    if pattern:
        raw_cname_block = pattern.group(1)
        matches = re.findall(r'CNAME\\t([^\"]+)', raw_cname_block)
        return [f"CNAME\t{c}" for c in matches] if matches else []
    return []

def parse_nuclei_output(stdout: str, meta: dict):
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    clean_stdout = ansi_escape.sub("", stdout)

    lines = clean_stdout.strip().splitlines()
    detections = defaultdict(set)

    for line in lines:
        if "[detect-dangling-s3-cname]" in line:
            if "[dns]" in line:
                match = re.search(r"\[dns\].*?(http[s]?://\S+|\S+)", line)
                if match:
                    domain = match.group(1).replace("http://", "").replace("https://", "")
                    detections[domain].add("dns")
            elif "[http]" in line:
                match = re.search(r"\[http\].*?(http[s]?://\S+)", line)
                if match:
                    domain = match.group(1).replace("http://", "").replace("https://", "")
                    detections[domain].add("http")

    confirmed_domains = [d for d, tags in detections.items() if {"dns", "http"} <= tags]
    base_domain = meta.get("target_url", "").replace("http://", "").replace("https://", "")
    final_success = infer_success(clean_stdout)
    cname_records = extract_all_cname_records(clean_stdout, base_domain)

    return {
        "tool_id": 1,
        "target": meta.get("target_url"),
        "command": meta.get("command"),
        "success": final_success,
        "vulnerability": "detect-dangling-s3-cname [dns] and [http] matched"
                         if final_success == 1 else "No vulnerable CNAME record detected",
        "risk_level": "high" if final_success == 1 else "info",
        "url": "\n".join(cname_records),       # 문자열 (DB용)
        "url_list": cname_records,             # 리스트 (프론트용)
        "log": extract_core_logs(clean_stdout),
        "start_time": meta.get("start_time"),
        "end_time": meta.get("end_time")
    }
