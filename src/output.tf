output "environment" {
  value = "Deploying to environment ${var.environment}: AWS Account ${local.account_id} - Region ${var.aws_region}"
}
