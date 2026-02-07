import boto3
import json
from collections import defaultdict

# === CONFIG ===
INPUT_BUCKET = "secure-log-analysis-logs"    # S3 bucket containing your input log
OUTPUT_BUCKET = "secure-log-analysis-output" # S3 bucket to save output
LOG_FILE_LOCAL = "/tmp/sample.log"           # Temporary local file on EC2
OUTPUT_FILE_LOCAL = "/tmp/output.json"       # Temporary output file on EC2

# === DOWNLOAD LOG FROM S3 ===
s3 = boto3.client('s3')
print(f"Downloading log file from S3 bucket '{INPUT_BUCKET}'...")
s3.download_file(INPUT_BUCKET, 'sample.log', LOG_FILE_LOCAL)
print("Download complete.")

# === ANALYSIS ===
failed_attempts = defaultdict(int)
FAILED_THRESHOLD = 2

with open(LOG_FILE_LOCAL, "r") as file:
    for line in file:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        status_code = parts[-1]
        if status_code == "403":
            failed_attempts[ip] += 1

suspicious_ips = [
    {"ip": ip, "failed_attempts": count}
    for ip, count in failed_attempts.items()
    if count > FAILED_THRESHOLD
]

output = {"suspicious_ips": suspicious_ips}

# === SAVE OUTPUT LOCALLY AND UPLOAD TO S3 ===
with open(OUTPUT_FILE_LOCAL, "w") as f:
    json.dump(output, f, indent=4)

s3.upload_file(OUTPUT_FILE_LOCAL, OUTPUT_BUCKET, 'output.json')
print(f"Analysis complete. Output uploaded to S3 bucket '{OUTPUT_BUCKET}'.")

# === OPTIONAL DEBUG ===
print("Suspicious IPs found:", suspicious_ips)
