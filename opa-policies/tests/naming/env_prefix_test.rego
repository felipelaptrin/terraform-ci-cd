package terraform.naming_test

import rego.v1

import data.terraform.naming

test_valid_name if {
  inp := {
    "resource_changes": [
      {
        "address": "aws_sqs_queue.terraform_queue",
        "mode": "managed",
        "type": "aws_sqs_queue",
        "change": {
          "actions": ["create"],
          "after": {
            "name": "dev-terraform-cicd",
            "tags_all": {
              "Environment": "dev",
              "Project": "Terraform CI/CD",
            },
          },
        },
      },
      {
        "address": "module.bucket.aws_s3_bucket.this",
        "mode": "managed",
        "type": "aws_s3_bucket",
        "change": {
          "actions": ["create"],
          "after": {
            "bucket": "dev-terraform-cd-ci-demo-123456789012",
            "tags_all": {
              "Environment": "dev",
              "Project": "Terraform CI/CD",
            },
          },
        },
      },
    ],
  }
  count(naming.deny) == 0 with input as inp
}

test_missing_prefix if {
  inp := {
    "resource_changes": [{
      "address": "aws_sqs_queue.terraform_queue",
      "mode": "managed",
      "type": "aws_sqs_queue",
      "change": {
        "actions": ["create"],
        "after": {
          "name": "my-queue",
          "tags_all": {
            "Environment": "dev",
            "Project": "Terraform CI/CD",
          },
        },
      },
    }],
  }
  result := naming.deny with input as inp
  count(result) > 0
  some msg in result
  contains(msg, "must start with the environment prefix")
}
