package terraform.s3_test

import rego.v1

import data.terraform.s3

test_valid_bucket_with_policy if {
  inp := {
    "resource_changes": [
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
      {
        "address": "module.bucket.aws_s3_bucket_policy.this",
        "mode": "managed",
        "type": "aws_s3_bucket_policy",
        "change": {
          "actions": ["create"],
          "after": {
            "bucket": "dev-terraform-cd-ci-demo-123456789012",
            "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyInsecureTransport\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::dev-terraform-cd-ci-demo-123456789012\",\"arn:aws:s3:::dev-terraform-cd-ci-demo-123456789012/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}",
          },
        },
      },
    ],
  }
  count(s3.deny) == 0 with input as inp
}

test_bucket_missing_policy if {
  inp := {
    "resource_changes": [{
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
    }],
  }
  result := s3.deny with input as inp
  count(result) > 0
  some msg in result
  contains(msg, "must have an aws_s3_bucket_policy enforcing SecureTransport")
}
