package terraform.tagging_test

import rego.v1

import data.terraform.tagging

test_valid_tags if {
  inp := {
    "resource_changes": [{
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
    }],
  }
  count(tagging.deny) == 0 with input as inp
}

test_missing_tags if {
  inp := {
    "resource_changes": [{
      "address": "aws_sqs_queue.terraform_queue",
      "mode": "managed",
      "type": "aws_sqs_queue",
      "change": {
        "actions": ["create"],
        "after": {
          "name": "dev-terraform-cicd",
          "tags_all": {"Project": "Terraform CI/CD"},
        },
      },
    }],
  }
  result := tagging.deny with input as inp
  count(result) > 0
  some msg in result
  contains(msg, "missing required tag(s)")
  contains(msg, "Environment")
}
