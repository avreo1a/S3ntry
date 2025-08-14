import boto3, os, logging, requests, json


def scan_s3():
    s3 = boto3.client('s3')

    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    findings = []


    # -- Check if the Bucket has Public Access Block enabled --
    for bucket in buckets:
        #Lets just assume Public Access Block is NOT enabled
        blocked = False
        try:
            pab = s3.get_public_access_block(Bucket=bucket)
            if pab.get("PublicAccessBlockConfiguration", {}).get("BlockPublicAcls", False):
                blocked = True

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            logging.warning(f"Public Access Block not configured for bucket: {bucket}")
            blocked = False

    #-- Check of the bucket polciy --
        star_get = False
        try:
            #get the bucket policy and place it into the dictionary
            pol = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
            for statement in pol.get("Statement", []):

                #Only check statments that allow access
                if statement.get("Effect") == "Allow":

                    principal = statement.get("Principal", {})
                    #Check if the principal is everyone
                    principal_star = principal == "*" or principal == {"AWS": "*"}
                    actions = statement.get("Action", [])


                    if isinstance(actions, str):
                        actions = [actions]
                        allow_get = "s3:GetObject" in actions or "S3:" in actions


                        if principal_star and allow_get:
                            star_get = True
                            break


        except s3.exceptions.from_code("NoSuchBucketPolicy"):

            pass

     # -- Check the Default Encryption --
        encrypted = True  
        try:
            # Fetch the default encryption configuration for the bucket
            enc = s3.get_bucket_encryption(Bucket=bucket)

            encrypted = bool(enc["ServerSideEncryptionConfiguration"]["Rules"])
        except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            # If encryption config is missing, mark as not encrypted
            encrypted = False






        # -- Record Findings --
        # If Block Public Access is missing OR policy is public OR encryption is missing:
        if (not blocked) or star_get or (not encrypted):
            findings.append({
                "bucket": bucket,                      # Name of the bucket
                "public_access_block": blocked,       # True if Block Public Access is on
                "public_policy": star_get,            # True if bucket policy is public
                "encrypted": encrypted                # True if default encryption is enabled
            })


    return findings



def lambda_handler(event, context):
  
    findings = scan_s3()

    
    if findings:
        #dump in findings and as json for CloduWatch
        print(json.dumps(findings, indent=2))
    else:
      
        print("No risky buckets found.")

   
    return {"findings": findings}