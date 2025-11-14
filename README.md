# Vulnerable-Environment-With-Automated-Remediator

This is a small personal project to get me more familiar with AWS and Cloud Security concepts. I recently got my AWS Cloud Practitioner Certification, but want to get some more hands on experience with the platform.

## Goal

To intentionally deploy a small insecure aws test environment and build a Lambda-based Remediator that automatically fixes common issues.
I will then schedule remediation checks with EventBridge.

I plan on also using this opportunity to get some experience using Terraform to do some simple provisioning.

### Step By Step Process

#### 1. Create the intentionally vulnerable resources

I started doing this manually originally. But I found the AWS Management console a bit cumbersome. Previously I had watched some videos on Terraform and figured this was a perfect time to try it out. After setting up terraform I used the Cursor IDE to help me write some code to provision the following:

1. An S3 Bucket with public-read access
2. An IAM User that does not have MFA setup
    1. An Access Key assigned to this user
3. A Security Group that has open-SSH

I ran into a few hiccups since this was my first time using terraform but ultimately got it to run successfully. I can see how this is a powerfull tool to provision large projects ESPECIALLY if they span across multiple platforms. I plan on using Terraform as much as I can

#### 2. Create Lambda remediation code

I then created some python code for lambda. This code had 3 main functions:

1. Remediate any Public S3 buckets
2. Remediate any open Security Groups
3. Revoke any IAM Access keys from users that did not have MFA

#### 3. Create IAM role to run Lambda code

After creating the code I wanted to make a role that would run the Lambda function. Since I am new to AWS permissions I just pasted my code into ChatGPT and asked it what the minimum required permissions were that could run this code. From there it gave me a JSON file that I could use to make a custom inline policy.

#### 4. Test and Deploy in Lambda

From here I pasted the Code into Lambda, and ran a test.

Test Results:

```
Status: Succeeded
Test Event Name: defaultTest

Response:
{
  "statusCode": 200,
  "body": "{\"remediation\": [\"Revoked 0.0.0.0/0 ingress on Security Group sg-039cec187c81a2875 ports 22-22\", \"Revoked 0.0.0.0/0 ingress on Security Group sg-05504bcb0f857b8e8 ports 22-22\", \"Deactivated access key AKIAXEWBND44CGUFGJ43 for user admin-user due to no MFA\", \"Deactivated access key AKIAXEWBND44KAEDGPZB for user vulnerable-no-mfa-user due to no MFA\"]}"
}

Function Logs:
START RequestId: 8ae5116c-55f6-4fc1-aba2-ba3c6de00928 Version: $LATEST
END RequestId: 8ae5116c-55f6-4fc1-aba2-ba3c6de00928
REPORT RequestId: 8ae5116c-55f6-4fc1-aba2-ba3c6de00928	Duration: 2020.12 ms	Billed Duration: 2817 ms	Memory Size: 128 MB	Max Memory Used: 103 MB	Init Duration: 795.98 ms

Request ID: 8ae5116c-55f6-4fc1-aba2-ba3c6de00928
```

If you have a sharp eye you will see that the test not only remediated all of my intentional vulnerabilities, but actually remediated an unintentional one: my admin_user (which I have been using for this project) did not have MFA activated either!

Once I verified the code worked I deployed it and scheduled it to run daily.
