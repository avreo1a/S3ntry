# S3Entry

**S3Entry** is a lightweight, open-source tool that scans your AWS S3 buckets for misconfigurations that could lead to data leaks — like the one that exposed the Tea app's data.  
It checks for:
- Publicly accessible buckets
- Insecure bucket policies (`Principal: "*"`)
- Missing encryption at rest

## Why?
Cloud storage misconfigurations are one of the top causes of data breaches. **S3Entry** helps you **find and fix risky S3 settings before attackers do**.

## Features (v1)
- Scans **all S3 buckets** in your AWS account
- Flags:
  - Missing Block Public Access
  - Wildcard public access in bucket policies
  - Buckets without encryption enabled
- Slack alerts with bucket details
- Runs manually or on a daily schedule via GitHub Actions

---

## Quick Start

### 1. Clone the repo
```bash
cd s3Entry
pip install -r requirements.txt

aws iam create-policy \
  --policy-name S3EntryScanReadOnly \
  --policy-document file://S3EntryScanReadOnly.json

'''