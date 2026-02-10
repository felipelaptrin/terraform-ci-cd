resource "aws_sqs_queue" "terraform_queue" {
  name                    = "test"
  sqs_managed_sse_enabled = true
}

module "bucket" {
  source      = "../modules/bucket"
  bucket_name = "terraform-cd-ci-demo-${local.account_id}"
}
