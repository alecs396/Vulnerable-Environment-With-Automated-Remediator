import boto3
import json
import os

s3 = boto3.client('s3')
ec2 = boto3.client('ec2')
iam = boto3.client('iam')

def remediate_public_s3(bucket_name):
    # Block public access
    try:
        s3.put_public_access_block(
            Bucket = bucket_name,
            PublicAccessBlockConfiguration = {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )

        # Set ACL to Private
        s3.put_bucket_acl(Bucket = bucket_name, ACL = 'private')
        return f"S3: {bucket_name} set to private and public access is blocked"
    except Exception as e:
        return f"S3 remediation error for {bucket_name}: {e}"

