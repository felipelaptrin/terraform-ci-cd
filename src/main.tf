resource "aws_sqs_queue" "terraform_queue" {
  name                    = "test"
  sqs_managed_sse_enabled = true
}
