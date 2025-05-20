# parses/parse_nmap.py

import re
import json
import os
from datetime import datetime, timedelta

def load_exploit_cve_map():
    base_dir = os.path.dirname(__file__)
    map_path = os.path.join(base_dir, "../data/exploit_cve_map.json")
    try:
        with open(map_path, "r") as f:
            return json.load(f)
    except:
        return {}

def parse_vulnerabilities(text: str, exploit_cve_map: dict):
    pattern = re.compile(r"""
        (?P<id>(CVE-\d{4}-\d+|CNVD-\d{4}-\d+|[A-Z0-9:-]{8,}))
        \s+
        (?P<score>\d+\.\d+|\d+)
        \s+
        (?P<url>https?://[^\s*]+)
    """, re.VERBOSE)

    vulnerabilities = []
    for match in pattern.finditer(text):
        vuln_id = match.group("id")
        score = float(match.group("score"))
        url = match.group("url")

        if vuln_id.startswith("CVE-"):
            id_type = "CVE"
            cve = vuln_id
        elif vuln_id.startswith("CNVD-"):
            id_type = "CNVD"
            cve = vuln_id
        elif vuln_id in exploit_cve_map:
            id_type = "exploit"
            cve = exploit_cve_map.get(vuln_id)
        else:
            id_type = "exploit"
            cve = None

        vulnerabilities.append({
            "id": vuln_id,
            "id_type": id_type,
            "score": score,
            "url": url,
            "cve": cve
        })

    return vulnerabilities

def parse_nmap_output(nmap_output: str, command: str, tool_id=1):
    results = []
    exploit_cve_map = load_exploit_cve_map()

    ip_match = re.search(r'Nmap scan report for [^\s]+ \(([\d.]+)\)', nmap_output)
    ip = ip_match.group(1) if ip_match else 'unknown'

    version_match = re.search(r'Starting Nmap\s+([\d.]+)', nmap_output)
    scanner_version = version_match.group(1) if version_match else "unknown"

    success_flag = 1 if "PORT" in nmap_output else 0

    start_time_match = re.search(r'^Starting Nmap.*?at (.+)$', nmap_output, re.MULTILINE)
    if start_time_match:
        try:
            start_time_str = start_time_match.group(1).strip()
            start_time = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M %Z")
        except:
            start_time = datetime.now()
    else:
        start_time = datetime.now()

    duration_match = re.search(r'Nmap done: .* scanned in ([\d.]+) seconds', nmap_output)
    elapsed_seconds = float(duration_match.group(1)) if duration_match else 5.0
    end_time = start_time + timedelta(seconds=elapsed_seconds)

    current_port = None
    current_service_info = ""
    port_section_started = False

    for line in nmap_output.strip().split('\n'):
        line = line.strip()

        if line.startswith("PORT"):
            port_section_started = True
            continue
        if not port_section_started or not line:
            continue

        port_line_match = re.match(r'^(\d+)/(\w+)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$', line)
        if port_line_match:
            if current_port:
                vulnerabilities = parse_vulnerabilities(current_service_info, exploit_cve_map)
                current_port["vulnerabilities"] = vulnerabilities
                results.append(current_port)

            port = int(port_line_match.group(1))
            protocol = port_line_match.group(2)
            status = port_line_match.group(3)
            service = port_line_match.group(4)
            version = port_line_match.group(5) if port_line_match.group(5) else "unknown"

            current_port = {
                "tool_id": tool_id,
                "target": ip,
                "command": command,
                "success": success_flag,
                "port_number": port,
                "port_status": status,
                "protocol": protocol,
                "service_name": service,
                "service_version": version.strip(),
                "logs": nmap_output,
                "start_time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
                "end_time": end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            current_service_info = ""
        elif current_port:
            current_service_info += line + "\n"

    if current_port:
        vulnerabilities = parse_vulnerabilities(current_service_info, exploit_cve_map)
        current_port["vulnerabilities"] = vulnerabilities
        results.append(current_port)

    return results
