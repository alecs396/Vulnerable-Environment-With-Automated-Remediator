terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# S3 Bucket with Public Read Access
resource "aws_s3_bucket" "public_bucket" {
  bucket = "vulnerable-public-bucket-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name        = "Vulnerable Public Bucket"
    Environment = "Vulnerable"
  }
}

# Random ID for unique bucket name
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Block public access settings (we'll override this to allow public read)
resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Bucket policy to allow public read access
resource "aws_s3_bucket_policy" "public_read_policy" {
  bucket = aws_s3_bucket.public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_bucket.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.public_bucket]
}

# Security Group with Open SSH (Port 22)
resource "aws_security_group" "open_ssh" {
  name        = "vulnerable-open-ssh-sg"
  description = "Security group with open SSH access (Vulnerable Configuration)"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "Vulnerable Open SSH Security Group"
    Environment = "Vulnerable"
  }
}

# IAM User with No MFA
resource "aws_iam_user" "no_mfa_user" {
  name = "vulnerable-no-mfa-user"
  
  tags = {
    Name        = "Vulnerable IAM User - No MFA"
    Environment = "Vulnerable"
  }
}

resource "aws_iam_access_key" "vuln_key" {
  user = aws_iam_user.no_mfa_user.name
}

# Outputs
output "s3_bucket_name" {
  description = "Name of the S3 bucket with public read access"
  value       = aws_s3_bucket.public_bucket.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.public_bucket.arn
}

output "security_group_id" {
  description = "ID of the security group with open SSH"
  value       = aws_security_group.open_ssh.id
}

output "iam_user_name" {
  description = "Name of the IAM user without MFA"
  value       = aws_iam_user.no_mfa_user.name
}

output "iam_access_key_id" {
  description = "ID of the Vulnerable IAM access key"
  value       = aws_iam_access_key.vuln_key.id
}

output "iam_user_arn" {
  description = "ARN of the IAM user"
  value       = aws_iam_user.no_mfa_user.arn
}

