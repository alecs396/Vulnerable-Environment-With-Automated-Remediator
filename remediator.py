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

def remediate_open_sgs():
    results = []
    sgs = ec2.describe_security_groups()['SecurityGroups']
    for sg in sgs:
        sg_id = sg['GroupId']
        for perm in sg.get('IpPermissions', []):
            for ip in perm.get('IpRanges', []):
                cidr = ip.get('CidrIp')
                
                # Detect any 0.0.0.0/0 entries
                if cidr == '0.0.0.0/0':
                    from_port = perm.get('FromPort')
                    to_port = perm.get('ToPort')
                    try:
                        ec2.revoke_security_group_ingress(GroupId = sg_id, IpPermissions = [perm])
                        results.append(f"Revoked {cidr} ingress on Security Group {sg_id} ports {from_port}-{to_port}")
                    except Exception as e:
                        results.append(f"Failed to revoke ingress on {sg_id}: {e}")

    return results

def lambda_handler(event, context):
    findings = []
    # 1) Check for public S3 buckets
    buckets = s3.list_buckets().get('Buckets', [])
    for b in buckets:
        bname = b['Name']
        try:
            acl = s3.get_bucket_acl(Bucket = bname)
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    findings.append(f"Bucket {bname} has public ACL")
                    findings.append(remediate_public_s3(bname))
                    break
        except Exception as e:
            findings.append(f"Error checking ACL for {bname}: {e}")

    # 2) Check for open security groups
    sg_results = remediate_open_sgs()
    findings.extend(sg_results)