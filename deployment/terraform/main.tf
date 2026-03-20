# ═══════════════════════════════════════════════════════════════════════════════
# AEGIS-SILENTIUM — Terraform Infrastructure
# Provisions short-lived relay VMs on a cloud provider (AWS default).
# Each relay is a hardened, minimal Ubuntu instance running the Go relay binary.
# Relays have no persistent state; destroy and rebuild regularly.
#
# AUTHORIZED USE ONLY — Provision only on infrastructure you own or have
# explicit written permission to use.
# ═══════════════════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
  # Remote state (recommended for team use)
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "aegis-silentium/relay/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region
}

# ── Random suffix for unique resource naming ────────────────────────────────
resource "random_id" "suffix" {
  byte_length = 4
}

# ── TLS: Generate ephemeral relay key pair ──────────────────────────────────
# In production, use cert-manager or ACME (Let's Encrypt) instead
resource "tls_private_key" "relay" {
  count     = var.relay_count
  algorithm = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "relay" {
  count           = var.relay_count
  private_key_pem = tls_private_key.relay[count.index].private_key_pem

  subject {
    common_name  = "relay${count.index + 1}.${var.relay_domain}"
    organization = "AEGIS-SILENTIUM"
  }

  validity_period_hours = var.cert_validity_hours
  early_renewal_hours   = 24

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# ── VPC ─────────────────────────────────────────────────────────────────────
resource "aws_vpc" "relay_vpc" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "aegis-relay-vpc-${random_id.suffix.hex}"
    Project     = "aegis-silentium"
    Environment = var.environment
    # Short TTL tag for automated cleanup
    DestroyAfter = timeadd(timestamp(), "${var.relay_ttl_hours}h")
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.relay_vpc.id
  tags   = { Name = "aegis-igw-${random_id.suffix.hex}" }
}

resource "aws_subnet" "relay_public" {
  vpc_id                  = aws_vpc.relay_vpc.id
  cidr_block              = "10.10.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]
  tags                    = { Name = "aegis-relay-public-${random_id.suffix.hex}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.relay_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "aegis-rt-public-${random_id.suffix.hex}" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.relay_public.id
  route_table_id = aws_route_table.public.id
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ── Security Group (relay) ──────────────────────────────────────────────────
resource "aws_security_group" "relay" {
  name        = "aegis-relay-sg-${random_id.suffix.hex}"
  description = "AEGIS-SILENTIUM relay security group"
  vpc_id      = aws_vpc.relay_vpc.id

  # Allow HTTPS from anywhere (implant connections)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from implants"
  }

  # Allow WireGuard from core only
  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = [var.core_ip_cidr]
    description = "WireGuard from Intelligence Core"
  }

  # SSH access from operator CIDR only (restrict tightly)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.operator_ip_cidr]
    description = "SSH operator access"
  }

  # All outbound (relay needs to reach core via WireGuard)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "aegis-relay-sg-${random_id.suffix.hex}"
    Project = "aegis-silentium"
  }
}

# ── EC2 Key Pair ─────────────────────────────────────────────────────────────
resource "tls_private_key" "ssh" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "relay" {
  key_name   = "aegis-relay-${random_id.suffix.hex}"
  public_key = tls_private_key.ssh.public_key_openssh
}

# ── AMI: Latest Ubuntu 24.04 LTS ────────────────────────────────────────────
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── Relay Instances ──────────────────────────────────────────────────────────
resource "aws_instance" "relay" {
  count         = var.relay_count
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.relay_instance_type
  key_name      = aws_key_pair.relay.key_name
  subnet_id     = aws_subnet.relay_public.id

  vpc_security_group_ids = [aws_security_group.relay.id]

  # Small root volume — relay is stateless
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 10
    encrypted             = true
    delete_on_termination = true
  }

  # User data: bootstrap relay binary + config
  user_data = templatefile("${path.module}/relay_userdata.sh.tpl", {
    relay_id        = "relay${count.index + 1}-${random_id.suffix.hex}"
    relay_cert_pem  = tls_self_signed_cert.relay[count.index].cert_pem
    relay_key_pem   = tls_private_key.relay[count.index].private_key_pem
    core_wg_ip      = var.core_wireguard_ip
    core_wg_pubkey  = var.core_wireguard_pubkey
    relay_wg_ip     = "10.99.0.${count.index + 2}"
    operator_key    = var.operator_key
    profile_name    = var.relay_profiles[count.index % length(var.relay_profiles)]
  })

  metadata_options {
    http_tokens   = "required"   # Require IMDSv2
    http_endpoint = "enabled"
  }

  # Disable detailed monitoring to reduce cost (enable for production)
  monitoring = false

  tags = {
    Name         = "aegis-relay-${count.index + 1}-${random_id.suffix.hex}"
    Project      = "aegis-silentium"
    Environment  = var.environment
    RelayIndex   = tostring(count.index + 1)
    DestroyAfter = timeadd(timestamp(), "${var.relay_ttl_hours}h")
  }

  lifecycle {
    # Prevent accidental replacement during planned operations
    ignore_changes = [user_data]
  }
}

# ── Elastic IPs (stable relay addresses) ─────────────────────────────────────
resource "aws_eip" "relay" {
  count    = var.relay_count
  instance = aws_instance.relay[count.index].id
  domain   = "vpc"

  tags = {
    Name    = "aegis-relay-eip-${count.index + 1}-${random_id.suffix.hex}"
    Project = "aegis-silentium"
  }
}

# ── CloudWatch: Auto-terminate after TTL ─────────────────────────────────────
resource "aws_cloudwatch_event_rule" "relay_ttl" {
  name                = "aegis-relay-ttl-${random_id.suffix.hex}"
  description         = "Auto-terminate AEGIS relays after TTL"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "relay_ttl" {
  rule      = aws_cloudwatch_event_rule.relay_ttl.name
  target_id = "TerminateRelays"
  arn       = aws_lambda_function.relay_terminator.arn
}

# Simple Lambda to terminate old relay instances
resource "aws_lambda_function" "relay_terminator" {
  filename         = "${path.module}/lambda/terminator.zip"
  function_name    = "aegis-relay-terminator-${random_id.suffix.hex}"
  role             = aws_iam_role.lambda_terminator.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = filebase64sha256("${path.module}/lambda/terminator.zip")

  environment {
    variables = {
      TAG_KEY   = "DestroyAfter"
      REGION    = var.aws_region
    }
  }
}

resource "aws_iam_role" "lambda_terminator" {
  name = "aegis-relay-terminator-role-${random_id.suffix.hex}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_ec2" {
  name = "ec2-terminate"
  role = aws_iam_role.lambda_terminator.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances", "ec2:TerminateInstances"]
      Resource = "*"
      Condition = {
        StringEquals = { "ec2:ResourceTag/Project" = "aegis-silentium" }
      }
    }]
  })
}
