#!/usr/bin/env python3
"""
Auto-detecting Nessus extractor.
Usage:
  python3 extract_nessus.py [optional_path_to_scan.nessus|scan.db]

If no arg given, script searches current dir then recursively for *.nessus or *.db
Outputs: critical_high_vulns_<basename>.csv
"""
import sys, os, csv, xml.etree.ElementTree as ET, sqlite3

def find_scan_file():
    # look in cwd first
    for ext in ("*.nessus", "*.db", "*.xml"):
        for f in sorted([fn for fn in os.listdir(".") if fn.lower().endswith(ext.replace('*',''))]):
            return os.path.abspath(f)
    # recursive fallback
    for root, dirs, files in os.walk("."):
        for name in files:
            if name.lower().endswith((".nessus", ".db", ".xml")):
                return os.path.abspath(os.path.join(root, name))
    return None

def parse_nessus_xml(path, out_csv):
    tree = ET.parse(path)
    root = tree.getroot()
    rows = []
    for report_host in root.findall(".//ReportHost"):
        host_name = report_host.get("name") or ""
        for item in report_host.findall("ReportItem"):
            try:
                severity = int(item.get("severity", 0))
            except:
                severity = 0
            if severity >= 3:
                port = item.get("port") or ""
                service = item.get("svc_name") or ""
                vuln = item.get("pluginName") or (item.findtext("pluginName") or (item.findtext("plugin") or ""))
                cve = item.findtext("cve") or ""
                solution = item.findtext("solution") or ""
                rows.append([host_name, port, service, vuln, severity, cve, solution])
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Host","Port","Service","Vulnerability","Severity","CVE","Solution"])
        writer.writerows(rows)
    print(f"[+] Wrote {len(rows)} rows to {out_csv}")

def sqlite_extract(path, out_csv):
    con = sqlite3.connect(path)
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [r[0] for r in cur.fetchall()]
    if not tables:
        print("[-] No tables in DB.")
        return
    preferred = ["report_items","report_item","report_items_v2","results","report"]
    chosen = next((t for t in preferred if t in tables), tables[0])
    cur.execute(f"PRAGMA table_info('{chosen}');")
    cols = [r[1] for r in cur.fetchall()]
    cols_l = [c.lower() for c in cols]
    mapping = {
        "host": ["host","hostname"],
        "port": ["port","port_number"],
        "svc_name": ["svc_name","service","svc"],
        "pluginName": ["pluginname","plugin_name","plugin"],
        "severity": ["severity","sev"],
        "cve": ["cve","cves"],
        "solution": ["solution","solutions"]
    }
    wanted = []
    for key,poss in mapping.items():
        for p in poss:
            if p in cols_l:
                wanted.append(cols[cols_l.index(p)])
                break
    if not wanted:
        wanted = cols
    if any(c.lower()=="severity" for c in cols_l):
        q = f"SELECT {', '.join(['\"'+c+'\"' for c in wanted])} FROM '{chosen}' WHERE severity >= 3"
    else:
        q = f"SELECT {', '.join(['\"'+c+'\"' for c in wanted])} FROM '{chosen}'"
    cur.execute(q)
    rows = cur.fetchall()
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(wanted)
        writer.writerows(rows)
    print(f"[+] Wrote {len(rows)} rows from table '{chosen}' to {out_csv}")
    con.close()

def main():
    if len(sys.argv) == 2:
        path = sys.argv[1]
        if not os.path.isfile(path):
            print(f"Error: file not found: {path}")
            sys.exit(1)
    else:
        path = find_scan_file()
        if not path:
            print("No .nessus or .db file found in current dir or subfolders. Place the scan file here or pass it as an argument.")
            sys.exit(1)
        print(f"[+] Auto-detected scan file: {path}")

    base = os.path.basename(path)
    out_csv = f"critical_high_vulns_{os.path.splitext(base)[0]}.csv"
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext in (".nessus", ".xml"):
            parse_nessus_xml(path, out_csv)
        else:
            sqlite_extract(path, out_csv)
    except Exception as e:
        print("[-] Error processing file:", e)
        sys.exit(1)

if __name__ == '__main__':
    main()
