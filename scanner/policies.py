# policy.py (skeleton)

import json
import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
from notify.AmazonSNS import SNSNotifier #TODO Not sure if I will use this however keep note its here

#For some reason I made this Type safe, Type safeis so silly
#Nevermind Python doesnt have typesafe so these are "Type Hints", mind you theyre not enforced and the runtime doesnt care
#none of this is tested btw

def _principal_is_public(principal: Any) -> bool:
    if principal == "*" and isinstance(principal, dict) and principal.get("AWS") == "*" and isinstance(principal, list) and any(p == "*" for p in principal):
        return True
    else:
        return False

def _listify(x: Any) -> List[str]:
    for x in x:
        if isinstance(x, str):
            return [x]
        elif isinstance(x, list):
            return x


def _get_buckets(s3) -> List[str]:
    listBuckets = []
    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    for bucket in buckets:
        listBuckets.append(bucket)
    return listBuckets


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
    # TODO Please check this function out idek if ts is functional fr LMAO (Logical : Edit 1 I did not fucking check lol)
    
    try:
        response = s3.get_bucket_policy_status(Bucket=bucket)
        return response.get("PolicyStatus", {}).get("IsPublic", False)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicyStatus':
            logging.warning(f"No bucket policy status for {bucket}.")
            return False
        else:
            logging.error(f"Error reading bucket policy status for {bucket}: {e}")
            raise
        
    
    
    
    
    
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
    try:
        response = s3.get_bucket_policy(Bucket=bucket)
        
        
        
    except:
        logging.error(f"Error reading bucket policy for {bucket}")
        
    return result


def _read_bucket_acl(s3, bucket: str) -> Dict[str, Any]:
    """
    Inspect ACL for public groups.
      Return: { "acl_public": bool, "grants_flagged": [ { "grantee": "...", "permission": "..." }, ... ] }
    """
    #Return all as false and empty list by default
    result = {"acl_public": False, "grants_flagged": []}
    
    try:
        response = s3.get_bucket_acl(Bucket=bucket)
        grants = response.get("Grants", [])
        
        
        for grant in grants:
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission", "")
            
            #taking grantee details
            grantee_uri = grantee.get("URI", "")
            grantee_type = grantee.get("Type", "")
            
            #Public access URIs
            all_users_uri = "http://acs.amazonaws.com/groups/global/AllUsers"
            auth_users_uri = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            
            if grantee_uri in [all_users_uri, auth_users_uri]:
                result["acl_public"] = True
                result["grants_flagged"].append({
                    "grantee": grantee_uri,
                    "permission": permission,
                    "type": grantee_type
                })
                
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            logging.warning(f"Bucket {bucket} does not exist")
        elif error_code == 'AccessDenied':
            logging.warning(f"Access denied reading ACL for bucket {bucket}")
        else:
            logging.error(f"Error reading bucket ACL for {bucket}: {e}")
            raise
    except Exception as e:
        logging.error(f"Unexpected error reading ACL for bucket {bucket}: {e}")
        
    return result


def _read_default_encryption(s3, bucket: str) -> Dict[str, Any]:
    """
    Return encryption posture.
      { "encrypted": bool, "algorithm": str|None, "kms_key_id": str|None }
    """
    
    result = {"encrypted": False, "algorithm": None, "kms_key_id": None}
    # TODO:
    try:
        response = s3.get_bucket_encryption(Bucket=bucket)
        encryptionRules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if encryptionRules:
            result["encrypted"] = True
            result["algorithm"] = encryptionRules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            result["kms_key_id"] = encryptionRules[0].get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            logging.info(f"No default encryption for bucket {bucket}")
        elif error_code == 'NoSuchBucket':
            logging.warning(f"Bucket {bucket} does not exist")
        elif error_code == 'AccessDenied':
            logging.warning(f"Access denied reading encryption for bucket {bucket}")
        else:
            logging.error(f"Error reading bucket encryption for {bucket}: {e}")
            raise
    except Exception as e:
        logging.error(f"Unexpected error reading encryption for bucket {bucket}: {e}")
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
    
    try:
        

        if findings:
            print(json.dumps(findings, indent=2, sort_keys=True))
            notifier = SNSNotifier()
            notifier.send_alert(findings)
            
        else:
            print("No risky buckets found.")
            
            
    except Exception as e:
            logging.error("Failed to send SNS notification: {e}")
        
        # Optional SNS notification:
        # try:
        #     notifier = SNSNotifier()
        #     notifier.send_alert(findings)
        # except Exception as e:
        #     logging.error(f"Failed to send SNS notification: {e}")


    return {"findings": findings}
