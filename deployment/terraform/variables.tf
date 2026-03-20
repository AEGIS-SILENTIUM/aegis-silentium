# AEGIS-SILENTIUM Terraform Variables

variable "aws_region" {
  description = "AWS region for relay deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment label"
  type        = string
  default     = "red-team-lab"
  validation {
    condition     = contains(["red-team-lab", "staging", "production"], var.environment)
    error_message = "Environment must be red-team-lab, staging, or production."
  }
}

variable "relay_count" {
  description = "Number of relay instances to provision"
  type        = number
  default     = 2
  validation {
    condition     = var.relay_count >= 1 && var.relay_count <= 10
    error_message = "relay_count must be between 1 and 10."
  }
}

variable "relay_instance_type" {
  description = "EC2 instance type for relays (t3.micro sufficient for most ops)"
  type        = string
  default     = "t3.micro"
}

variable "relay_domain" {
  description = "Base domain for relay TLS certificates"
  type        = string
  default     = "relay.example.com"
}

variable "relay_ttl_hours" {
  description = "Hours before relay instances are automatically terminated"
  type        = number
  default     = 72   # 3 days
  validation {
    condition     = var.relay_ttl_hours >= 1 && var.relay_ttl_hours <= 720
    error_message = "TTL must be between 1 and 720 hours."
  }
}

variable "cert_validity_hours" {
  description = "Hours TLS certificates remain valid"
  type        = number
  default     = 168  # 7 days
}

variable "operator_ip_cidr" {
  description = "CIDR for operator SSH access (restrict tightly)"
  type        = string
  default     = "0.0.0.0/0"  # CHANGE THIS to your operator IP
}

variable "core_ip_cidr" {
  description = "CIDR block containing the Intelligence Core (for WireGuard)"
  type        = string
  default     = "10.0.0.0/8"
}

variable "core_wireguard_ip" {
  description = "WireGuard endpoint of the Intelligence Core (IP:port)"
  type        = string
  default     = "CHANGE_TO_CORE_IP:51820"
}

variable "core_wireguard_pubkey" {
  description = "WireGuard public key of the Intelligence Core"
  type        = string
  default     = "CHANGE_TO_CORE_WG_PUBKEY"
  sensitive   = true
}

variable "operator_key" {
  description = "AEGIS operator authentication key"
  type        = string
  sensitive   = true
  default     = "CHANGE_THIS_OPERATOR_KEY"
}

variable "relay_profiles" {
  description = "Malleable C2 profile names to assign to relays (cycled)"
  type        = list(string)
  default     = ["default", "google-analytics", "microsoft-teams"]
}

variable "tags" {
  description = "Additional tags applied to all resources"
  type        = map(string)
  default     = {}
}
