# policy.py (skeleton)

import json
import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
# from notify.AmazonSNS import SNSNotifier  # optional




def _principal_is_public(principal: Any) -> bool:
    if principal == "*" and isinstance(principal, dict) and principal.get("AWS") == "*" and isinstance(principal, list) and any(p == "*" for p in principal):
        return True
    else:
        return False

def _listify(x: Any) -> List[str]:
    """Normalize a string or list to a list of strings."""
    # TODO: implement
    return []


def _get_buckets(s3) -> List[str]:
    listBuckets = []
    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    for bucket in buckets:
        listBuckets.append(bucket)
        
        
        
        
        
    # TODO: list buckets via s3.list_buckets()
    return []


def _read_public_access_block(s3, bucket: str) -> Dict[str, bool]:
    """
    Return dict with the four PAB flags. If missing or error, default to False.
      {
        "BlockPublicAcls": bool,
        "IgnorePublicAcls": bool,
        "BlockPublicPolicy": bool,
        "RestrictPublicBuckets": bool
      }
    """
    cfg = {"BlockPublicAcls": False, "IgnorePublicAcls": False,
           "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    # TODO: call get_public_access_block and populate cfg
    # TODO: handle NoSuchPublicAccessBlockConfiguration via ClientError
    return cfg


def _read_bucket_policy_status(s3, bucket: str) -> bool:
    """Return True if AWS reports PolicyStatus.IsPublic = True, else False/None."""
    # TODO: call get_bucket_policy_status; handle ClientError
    return False


def _scan_bucket_policy(s3, bucket: str) -> Dict[str, Any]:
    """
    Inspect bucket policy. Return:
      {
        "policy_present": bool,
        "public_allow": bool,
        "public_allow_details": [ { "actions": [...], "resources": [...], "condition_present": bool }, ... ]
      }
    """
    result = {"policy_present": False, "public_allow": False, "public_allow_details": []}
    # TODO:
    #  - get_bucket_policy
    #  - json.loads
    #  - normalize Statement to list
    #  - for each Allow stmt with public principal, collect actions/resources/condition flag
    #  - set flags accordingly; handle NoSuchBucketPolicy via ClientError
    return result


def _read_bucket_acl(s3, bucket: str) -> Dict[str, Any]:
    """
    Inspect ACL for public groups.
      Return: { "acl_public": bool, "grants_flagged": [ { "grantee": "...", "permission": "..." }, ... ] }
    """
    result = {"acl_public": False, "grants_flagged": []}
    # TODO:
    #  - get_bucket_acl
    #  - check grantee URIs for AllUsers/AuthenticatedUsers
    #  - collect flagged grants
    #  - handle ClientError
    return result


def _read_default_encryption(s3, bucket: str) -> Dict[str, Any]:
    """
    Return encryption posture.
      { "encrypted": bool, "algorithm": str|None, "kms_key_id": str|None }
    """
    result = {"encrypted": False, "algorithm": None, "kms_key_id": None}
    # TODO:
    #  - get_bucket_encryption
    #  - parse Rules[0].ApplyServerSideEncryptionByDefault
    #  - handle ServerSideEncryptionConfigurationNotFoundError via ClientError
    return result


def _decide_risky(pab: Dict[str, bool],
                  policy_status_public: bool,
                  policy_scan: Dict[str, Any],
                  acl_scan: Dict[str, Any],
                  enc_scan: Dict[str, Any]) -> bool:
    """
    Decide if a bucket should be flagged.
    Typical reasons:
      - Not all PAB flags True
      - PolicyStatus.IsPublic True
      - Policy has public Allow
      - ACL is public
      - Default encryption disabled
    """
    # TODO: implement decision logic
    return False


def scan_s3() -> List[Dict[str, Any]]:
    """
    Scan all buckets and return a list of findings for buckets with issues.
    Each finding example:
      {
        "bucket": "...",
        "public_access_block": {...},
        "policy_status_is_public": bool|None,
        "policy": {...},
        "acl": {...},
        "encryption": {...}
      }
    """
    logging.getLogger().setLevel(logging.INFO)
    s3 = boto3.client("s3")

    findings: List[Dict[str, Any]] = []

    buckets = _get_buckets(s3)
    for bucket in buckets:
        pab = _read_public_access_block(s3, bucket)
        policy_status_public = _read_bucket_policy_status(s3, bucket)
        policy_scan = _scan_bucket_policy(s3, bucket)
        acl_scan = _read_bucket_acl(s3, bucket)
        enc_scan = _read_default_encryption(s3, bucket)

        if _decide_risky(pab, policy_status_public, policy_scan, acl_scan, enc_scan):
            findings.append({
                "bucket": bucket,
                "public_access_block": pab,
                "policy_status_is_public": policy_status_public,
                "policy": policy_scan,
                "acl": acl_scan,
                "encryption": enc_scan,
            })

    return findings


def lambda_handler(event, context):
    logging.basicConfig(level=logging.INFO)
    findings = scan_s3()

    if findings:
        print(json.dumps(findings, indent=2, sort_keys=True))
        # Optional SNS notification:
        # try:
        #     notifier = SNSNotifier()
        #     notifier.send_alert(findings)
        # except Exception as e:
        #     logging.error(f"Failed to send SNS notification: {e}")
    else:
        print("No risky buckets found.")

    return {"findings": findings}
