import os
import json
from collections import defaultdict

# Get the directory of the current script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Paths to the log file and output
LOG_FILE = os.path.join(BASE_DIR, "../logs/sample.log")
OUTPUT_FILE = os.path.join(BASE_DIR, "../logs/output.json")

#Dictionary to count failed attempts per IP
failed_attempts = defaultdict(int)

#Threshold for suspicious activity
FAILED_THRESHOLD = 2

#Read and parse log file
with open(LOG_FILE, "r") as file:
    for line in file:
        parts = line.strip().split()
        if len(parts) < 2:
            continue #skip malformed lines
        ip = parts[0]
        status_code = parts[-1]
        if status_code == "403": #failed attempt
            failed_attempts[ip] += 1

#Build the suspicious IPs list
suspicious_ips = [
    {"ip": ip, "failed_attempts": count}
    for ip, count in failed_attempts.items()
    if count > FAILED_THRESHOLD
]

#Output to JSON
output = {"suspicious_ips": suspicious_ips}
with open(OUTPUT_FILE, "w") as f:
    json.dump(output, f, indent=4)

print(f"Analysis complete. Results saved to {OUTPUT_FILE}")
