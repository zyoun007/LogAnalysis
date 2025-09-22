#!/usr/bin/env python3
from pathlib import Path
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

DATA_DIR = Path('data')
OUT_DIR = Path('outputs')
OUT_DIR.mkdir(parents=True, exist_ok=True)

AUTH_LOG = DATA_DIR / 'auth.log'
ACCESS_LOG = DATA_DIR / 'access.log'

def parse_auth(auth_path):
    failed_re = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+)")
    success_re = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.]+)")
    failures, successes = [], []
    for ln in auth_path.read_text().splitlines():
        if len(ln) < 15: 
            continue
        ts_part = ln[:15]
        try:
            ts_dt = datetime.strptime('2025 ' + ts_part, '%Y %b %d %H:%M:%S')
        except Exception:
            ts_dt = None
        m = failed_re.search(ln)
        if m:
            failures.append({'ts': ts_dt, 'user': m.group('user'), 'ip': m.group('ip')})
        m2 = success_re.search(ln)
        if m2:
            successes.append({'ts': ts_dt, 'user': m2.group('user'), 'ip': m2.group('ip')})
    return failures, successes

def parse_access(access_path):
    clf_re = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]+" (?P<status>\d{3}) (?P<size>\d+|-) "[^"]*" "(?P<ua>[^"]*)"')
    rows = []
    for ln in access_path.read_text().splitlines():
        m = clf_re.search(ln)
        if m:
            rows.append(m.groupdict())
    return rows

def write_csv(path, rows, headers):
    import csv
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in rows:
            w.writerow([r.get(h, '') for h in headers])

failures, successes = parse_auth(AUTH_LOG)
web = parse_access(ACCESS_LOG)

by_ip = Counter(f['ip'] for f in failures)
by_user = Counter(f['user'] for f in failures)
top_ip_counts = by_ip.most_common(10)

flagged = set()
ip_times = defaultdict(list)
for f in failures:
    if f['ts']:
        ip_times[f['ip']].append(f['ts'])
for ip, ts_list in ip_times.items():
    ts_list.sort()
    j = 0
    for i in range(len(ts_list)):
        while j < len(ts_list) and (ts_list[j] - ts_list[i]) <= timedelta(minutes=10):
            j += 1
        if (j - i) >= 5:
            flagged.add(ip); break


sus_paths = {'/admin','/admin/login','/wp-login.php','/phpmyadmin'}
web_suspicious = [w for w in web if w['path'] in sus_paths or 'sqlmap' in w['ua'].lower() or 'zmeu' in w['ua'].lower()]


auth_ips = set(by_ip.keys())
web_ips = set(w['ip'] for w in web)
overlap = sorted(auth_ips & web_ips)


ssh_top_path = OUT_DIR / "ssh_failures_top_ips.csv"
write_csv(ssh_top_path, [{'ip':ip,'count':cnt} for ip,cnt in top_ip_counts], ['ip','count'])

web_sus_path = OUT_DIR / "web_suspicious.csv"
write_csv(web_sus_path, web_suspicious, ['ip','ts','method','path','status','ua'])

with open(OUT_DIR / "overlap_ips.txt", "w") as f:
    for ip in overlap:
        f.write(ip + "\n")


with open(OUT_DIR / "summary.txt", "w") as f:
    f.write("== SSH Authentication (auth.log) ==\n")
    f.write(f"Total failed logins: {sum(by_ip.values())}\n")
    f.write(f"Top failed username(s): {', '.join(u for u,_ in by_user.most_common(5))}\n")
    f.write("Top attacker IPs (count):\n")
    for ip, cnt in top_ip_counts:
        f.write(f"  - {ip}: {cnt}\n")
    if flagged:
        f.write(f"Potential brute-force IPs (>=5 fails within 10m): {', '.join(sorted(flagged))}\n")
    else:
        f.write("Potential brute-force IPs: none detected at this threshold.\n")
    f.write("\n== Web Access (access.log) ==\n")
    f.write(f"Total requests: {len(web)}\n")
    f.write(f"Suspicious requests recorded: {len(web_suspicious)}\n")
    tool_uas = sorted(set(w['ua'] for w in web_suspicious if w['ua']))
    if tool_uas:
        f.write("Tool-like user-agents observed:\n")
        for ua in tool_uas:
            f.write(f"  - {ua}\n")
    f.write("\n== Cross-Log Indicators ==\n")
    if overlap:
        f.write("IPs observed in BOTH logs:\n")
        for ip in overlap:
            f.write(f"  - {ip}\n")
    else:
        f.write("No overlapping IPs found.\n")
print(f'Wrote outputs to: {OUT_DIR}')
