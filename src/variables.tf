variable "aws_region" {
  description = "Region to deploy the resources"
  type        = string
}

variable "environment" {
  description = "Environment name used to prefix resources"
  type        = string

  validation {
    condition     = contains(["local", "dev", "prod"], var.environment)
    error_message = "Allowed environments: local, dev, prod"
  }
}
