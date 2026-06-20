provider "aws" {
  region = var.aws_region

  # Configure for Floci when using local environment
  skip_credentials_validation = var.environment == "local" ? true : false
  skip_metadata_api_check     = var.environment == "local" ? true : false
  s3_use_path_style           = var.environment == "local" ? true : false

  # Set credentials for local environment
  access_key = var.environment == "local" ? "test" : null
  secret_key = var.environment == "local" ? "test" : null

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "Terraform CI/CD"
    }
  }
}
