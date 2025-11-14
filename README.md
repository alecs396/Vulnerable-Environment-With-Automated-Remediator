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
3. A Security Group that has open-SSH

I ran into a few hiccups since this was my first time using terraform but ultimately got it to run successfully. I can see how this is a powerfull tool to provision large projects ESPECIALLY if they span across multiple platforms. I plan on using Terraform as much as I can

#### 2. Create IAM role to run Lambda code

Next was creating an IAM role with the minimum privledges needed to run the remidiator. For this I used the AWS console, created a new role, and assigned it the following policies:

-   IAMReadOnlyAccess
-   AmazonSNSFullAccess
-   CloudWatchLogsFullAccess

#### 3. Create Lambda remediation code
