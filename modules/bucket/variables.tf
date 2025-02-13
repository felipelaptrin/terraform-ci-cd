variable "bucket_name" {
  description = "Name of the bucket"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key that will encrypt the S3 bucket"
  type        = string
}