# secure-log-analysis-aws
Python-based secure log analysis workflow deployed in AWS

## AWS Cloud Deployment

- Logs stored in S3 input bucket (`secure-log-analysis-logs`)
- EC2 instance with IAM role runs log analyser script
- Output uploaded to S3 output bucket (`secure-log-analysis-output`)
- Python 3 + boto3 used for automation
