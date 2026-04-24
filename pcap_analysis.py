"""
PCAP ANALYSER (COMBINED VERSION + SINGLE CSV EXPORT)
-----------------------------------------------------
This script performs both:
1. General traffic analysis (protocols, IPs, DNS, HTTP)
2. Basic intrusion detection (port scans, SYN floods, plaintext leaks)
3. Exports ALL results into one structured CSV with a 'section' column

Usage:
    python pcap_analyser.py <file.pcap>

Output:
    <file>_report.csv  →  All sections in one file, separated by a 'section' column
"""

import pyshark
import sys
import csv
import os
import re
from collections import Counter, defaultdict

import asyncio

try:
    asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
# -------------------------------
# 1. INPUT VALIDATION
# -------------------------------
if len(sys.argv) < 2:
    print("Usage: python pcap_analyser.py <file.pcap>")
    sys.exit(1)

pcap_file = sys.argv[1]
base_name = os.path.splitext(pcap_file)[0]
csv_file  = f"{base_name}_report.csv"

print(f"\n--- FULL ANALYSIS: {pcap_file} ---")


# -------------------------------
# 2. INITIALISE DATA STRUCTURES
# -------------------------------
packet_count      = 0
protocols         = Counter()
src_ips           = Counter()
dst_ips           = Counter()
dns_queries       = []
http_hosts        = []
port_scans        = defaultdict(set)
syn_counts        = Counter()
alerts            = []
sensitive_records = []

SENSITIVE_KEYWORDS = [
    'password', 'passwd', 'pass=', 'pwd',
    'user', 'username', 'login', 'logon',
    'authorization', 'auth', 'token',
    'credential', 'secret', 'api_key', 'apikey',
]

CRED_PATTERN = re.compile(
    r'(?:' + '|'.join(re.escape(k) for k in SENSITIVE_KEYWORDS) + r')'
    r'[=:\s]+([^\s&\r\n"\'<>]{1,80})',
    re.IGNORECASE
)

# -------------------------------
# 3. LOAD PCAP FILE
# -------------------------------
capture = pyshark.FileCapture(pcap_file, keep_packets=False)
print("Processing packets... (this may take some time)\n")


# -------------------------------
# 4. MAIN ANALYSIS LOOP
# -------------------------------
for packet in capture:
    packet_count += 1
    layer = packet.highest_layer
    protocols[layer] += 1

    src, dst = None, None

    if 'IP' in packet:
        src = packet.ip.src
        dst = packet.ip.dst
        src_ips[src] += 1
        dst_ips[dst] += 1

        if 'TCP' in packet:
            port_scans[src].add(packet.tcp.dstport)
            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                syn_counts[src] += 1
        elif 'UDP' in packet:
            port_scans[src].add(packet.udp.dstport)

    if 'DNS' in packet and hasattr(packet.dns, 'qry_name'):
        dns_queries.append(packet.dns.qry_name)

    if 'HTTP' in packet and hasattr(packet.http, 'host'):
        http_hosts.append(packet.http.host)

    if layer in ['HTTP', 'FTP', 'TELNET']:
        payload = str(packet).lower()
        matched_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in payload]

        if matched_keywords:
            if src:
                alerts.append(
                    f"[PLAINTEXT] Sensitive data found in {layer} traffic from {src}"
                )
            full_payload = str(packet)
            for kw in matched_keywords:
                kw_pattern = re.compile(
                    re.escape(kw) + r'[=:\s]+([^\s&\r\n"\'<>]{1,80})',
                    re.IGNORECASE
                )
                kw_match = kw_pattern.search(full_payload)
                extracted = kw_match.group(1).strip() if kw_match else '(no value extracted)'
                sensitive_records.append({
                    'packet_num':      packet_count,
                    'protocol':        layer,
                    'src_ip':          src or 'N/A',
                    'dst_ip':          dst or 'N/A',
                    'keyword':         kw,
                    'extracted_value': extracted,
                })

capture.close()


# -------------------------------
# 5. POST-PROCESSING
# -------------------------------
for ip, ports in port_scans.items():
    if len(ports) > 20:
        alerts.append(f"[ATTACK] Port scan detected from {ip} (targeted {len(ports)} ports)")

for ip, count in syn_counts.items():
    if count > 100:
        alerts.append(f"[ATTACK] SYN flood suspected from {ip} ({count} SYN packets)")


# -------------------------------
# 6. TERMINAL OUTPUT
# -------------------------------
print("=" * 60)
print(f"{'GENERAL NETWORK STATISTICS':^60}")
print("=" * 60)
print(f"Total Packets Analysed: {packet_count}")
print(f"Unique Protocols:       {len(protocols)}")

print("\n" + "-" * 40)
print(f"{'Protocol':<25} | {'Count':<10}")
print("-" * 40)
for proto, count in protocols.most_common(10):
    print(f"{proto:<25} | {count:<10}")

print("\n" + "-" * 40)
print(f"{'Top Source IPs':<25} | {'Packets':<10}")
print("-" * 40)
for ip, count in src_ips.most_common(5):
    print(f"{ip:<25} | {count:<10}")

print("\n" + "-" * 40)
print(f"{'Top Destination IPs':<25} | {'Packets':<10}")
print("-" * 40)
for ip, count in dst_ips.most_common(5):
    print(f"{ip:<25} | {count:<10}")

if dns_queries:
    print("\n" + "-" * 40)
    print("Top DNS Queries")
    print("-" * 40)
    for query, count in Counter(dns_queries).most_common(5):
        print(f"{query} ({count})")

if http_hosts:
    print("\n" + "-" * 40)
    print("HTTP Hosts Found")
    print("-" * 40)
    for host in set(http_hosts):
        print(host)

print("\n" + "=" * 60)
print(f"{'SECURITY & ATTACK ANALYSIS':^60}")
print("=" * 60)
if not alerts:
    print("No suspicious activity detected.")
else:
    for alert in set(alerts):
        print(f"!! {alert}")

print("\n" + "=" * 60)
print(f"{'SENSITIVE DATA FOUND IN PLAINTEXT TRAFFIC':^60}")
print("=" * 60)
if not sensitive_records:
    print("No sensitive data detected.")
else:
    print(f"{'#':<6} {'Proto':<8} {'Src IP':<18} {'Keyword':<16} {'Extracted Value'}")
    print("-" * 75)
    for r in sensitive_records:
        print(
            f"{r['packet_num']:<6} {r['protocol']:<8} "
            f"{r['src_ip']:<18} {r['keyword']:<16} {r['extracted_value']}"
        )

print("\n" + "=" * 60)
print(f"{'ANALYSIS COMPLETE':^60}")
print("=" * 60)


# -------------------------------
# 7. EXPORT TO SINGLE CSV
# -------------------------------
# All sections share the same columns; unused columns are blank per row.
# Use the 'section' column to filter in Excel / pandas.
#
# Column meanings per section:
#
#   SUMMARY        label=metric_or_protocol   value1=count
#   SOURCE_IPS     label=ip                   value1=packet_count
#   DEST_IPS       label=ip                   value1=packet_count
#   DNS_QUERIES    label=domain               value1=query_count
#   HTTP_HOSTS     label=host                 value1=request_count
#   ALERTS         label=alert_message
#   SENSITIVE_DATA label=packet_num           value1=protocol
#                  value2=src_ip              value3=dst_ip
#                  value4=keyword             value5=extracted_value

FIELDNAMES = ['section', 'label', 'value1', 'value2', 'value3', 'value4', 'value5']

def row(section, label, v1='', v2='', v3='', v4='', v5=''):
    return {
        'section': section,
        'label':   label,
        'value1':  v1,
        'value2':  v2,
        'value3':  v3,
        'value4':  v4,
        'value5':  v5,
    }

rows = []

# ── SUMMARY ──────────────────────────────────────────────────────────────────
rows.append(row('SUMMARY', 'total_packets',     packet_count))
rows.append(row('SUMMARY', 'unique_protocols',  len(protocols)))
for proto, count in protocols.most_common():
    rows.append(row('SUMMARY', proto, count))

# ── SOURCE_IPS ───────────────────────────────────────────────────────────────
for ip, count in src_ips.most_common(20):
    rows.append(row('SOURCE_IPS', ip, count))

# ── DEST_IPS ─────────────────────────────────────────────────────────────────
for ip, count in dst_ips.most_common(20):
    rows.append(row('DEST_IPS', ip, count))

# ── DNS_QUERIES ──────────────────────────────────────────────────────────────
for domain, count in Counter(dns_queries).most_common():
    rows.append(row('DNS_QUERIES', domain, count))

# ── HTTP_HOSTS ───────────────────────────────────────────────────────────────
for host, count in Counter(http_hosts).most_common():
    rows.append(row('HTTP_HOSTS', host, count))

# ── ALERTS ───────────────────────────────────────────────────────────────────
for alert in set(alerts):
    rows.append(row('ALERTS', alert))

# ── SENSITIVE_DATA ───────────────────────────────────────────────────────────
for r in sensitive_records:
    rows.append(row(
        'SENSITIVE_DATA',
        r['packet_num'],
        r['protocol'],
        r['src_ip'],
        r['dst_ip'],
        r['keyword'],
        r['extracted_value'],
    ))

# Write single CSV
with open(csv_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
    writer.writeheader()
    writer.writerows(rows)

print(f"\n[CSV] Full report saved → {csv_file}")