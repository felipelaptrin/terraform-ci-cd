package compliance.amazon_s3.ssl_test

import future.keywords.if
import future.keywords.in

import data.compliance.amazon_s3.ssl

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
  count(ssl.deny) == 0 with input as inp
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
  result := ssl.deny with input as inp
  count(result) > 0
  some msg in result
  contains(msg, "has no bucket policy")
}

test_bucket_policy_missing_secure_transport if {
  inp := {
    "resource_changes": [
      {
        "address": "module.bucket.aws_s3_bucket.this",
        "mode": "managed",
        "type": "aws_s3_bucket",
        "change": {
          "actions": ["create"],
          "after": {"bucket": "dev-terraform-cd-ci-demo-123456789012"},
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
            "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::dev-terraform-cd-ci-demo-123456789012/*\"}]}",
          },
        },
      },
    ],
  }
  result := ssl.deny with input as inp
  count(result) > 0
  some msg in result
  contains(msg, "does not enforce SSL/TLS")
}

test_noop_bucket_no_deny if {
  inp := {
    "resource_changes": [{
      "address": "module.bucket.aws_s3_bucket.this",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "change": {
        "actions": ["no-op"],
        "after": {"bucket": "dev-terraform-cd-ci-demo-123456789012"},
      },
    }],
  }
  count(ssl.deny) == 0 with input as inp
}
