import socket
import re
import threading

# ============================================
# 1. PORT SCAN + BANNER GRABBING
# ============================================

def scan_port(target, port):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((target, port))

        # Try to grab banner
        try:
            banner = s.recv(1024).decode(errors="ignore").strip()
        except:
            banner = "No Banner"
        s.close()

        return True, banner
    except:
        return False, None


# ============================================
# 2. LOAD LOCAL CVE DATABASE
# ============================================

def load_cve_database(path="cve-database.txt"):
    database = []
    with open(path, "r") as file:
        for line in file:
            parts = line.strip().split("|")
            if len(parts) == 4:
                service, cve, level, desc = [p.strip() for p in parts]
                database.append({
                    "service": service,
                    "cve": cve,
                    "level": level,
                    "desc": desc
                })
    return database


# ============================================
# 3. MATCH BANNER TO CVE DATABASE ENTRY
# ============================================

def check_vulnerability(banner, db):
    found = []
    for entry in db:
        if entry["service"].lower() in banner.lower():
            found.append(entry)
    return found


# ============================================
# 4. THREADING WRAPPER FOR FASTER SCAN
# ============================================

open_ports = []

def threaded_scan(target, port, db):
    status, banner = scan_port(target, port)
    if status:
        print(f"[+] Port {port} OPEN | Banner: {banner}")
        vulns = check_vulnerability(banner, db)

        if vulns:
            for v in vulns:
                print(f"   -> Vulnerability: {v['cve']} ({v['level']})")
                print(f"      Desc: {v['desc']}")
        else:
            print("   -> No known vulnerabilities.")

        open_ports.append((port, banner))


# ============================================
# 5. MAIN SCANNER
# ============================================

def run_scan(target):
    print(f"\n========== SIMPLE VULNERABILITY SCANNER by Aulia Tauhid ==========")
    print(f"Scanning target: {target}")
    print("=================================================\n")

    db = load_cve_database()

    threads = []

    for port in range(1, 1025):
        t = threading.Thread(target=threaded_scan, args=(target, port, db))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\n============ SCAN COMPLETE ============\n")
    print("Open Ports:")
    for port, banner in open_ports:
        print(f" - {port}/tcp | Banner: {banner}")


# ============================================
# 6. ENTRY POINT
# ============================================

if __name__ == "__main__":
    target = input("Enter target IP: ").strip()
    run_scan(target)
