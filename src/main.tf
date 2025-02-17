resource "aws_kms_key" "s3" {
  description = "KMS key user to encrypt buckets"
}

module "bucket-test" {
  source = "../modules/bucket"

  bucket_name = "test"
  kms_key_arn = aws_kms_key.s3.arn
}

resource "aws_sqs_queue" "terraform_queue" {
  name                    = "test"
  sqs_managed_sse_enabled = true
}
