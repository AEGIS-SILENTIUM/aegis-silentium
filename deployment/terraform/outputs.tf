# AEGIS-SILENTIUM Terraform Outputs

output "relay_public_ips" {
  description = "Public IP addresses of relay instances"
  value       = aws_eip.relay[*].public_ip
}

output "relay_instance_ids" {
  description = "EC2 instance IDs of relays (for manual termination)"
  value       = aws_instance.relay[*].id
}

output "relay_https_urls" {
  description = "HTTPS URLs for relay endpoints (configure in implant)"
  value       = [for ip in aws_eip.relay[*].public_ip : "https://${ip}:443"]
}

output "ssh_private_key" {
  description = "SSH private key for relay access (store securely, delete after use)"
  value       = tls_private_key.ssh.private_key_openssh
  sensitive   = true
}

output "relay_tls_certs" {
  description = "Self-signed TLS certificate PEMs for each relay"
  value       = tls_self_signed_cert.relay[*].cert_pem
  sensitive   = false
}

output "deployment_id" {
  description = "Unique identifier for this deployment"
  value       = random_id.suffix.hex
}

output "destroy_command" {
  description = "Command to destroy all relay infrastructure"
  value       = "terraform destroy -var-file=terraform.tfvars"
}

output "implant_config_snippet" {
  description = "Paste this into silentium.conf [c2] relay_urls"
  value       = join(",", [for ip in aws_eip.relay[*].public_ip : "https://${ip}:443"])
}
