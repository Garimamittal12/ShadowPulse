# detector_runner.py
import os
import subprocess
import sys
import time

DETECTORS_DIR = os.path.join(os.path.dirname(__file__), "detectors")

def run_detectors():
    scripts = [
        "arp_spoof.py",
        "dhcp_spoofing.py",
        "dns_spoof.py",
        "http_injection.py",
        "icmp_redirect.py",
        "rogue_access.py",  
        "ssl_strip.py"
    ]

    processes = []
    try:
        for script in scripts:
            script_path = os.path.join(DETECTORS_DIR, script)
            if not os.path.isfile(script_path):
                print(f"[WARN] Missing: {script_path}")
                continue

            print(f"[INFO] Starting detector: {script}")
            p = subprocess.Popen([sys.executable, script_path])
            processes.append(p)

        # Keep script running
        while True:
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[INFO] Stopping all detectors...")
        for p in processes:
            p.terminate()
        print("[INFO] All detectors stopped.")

if __name__ == "__main__":
    run_detectors()
