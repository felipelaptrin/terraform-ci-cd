package compliance.general.tagging_test

import future.keywords.if
import future.keywords.in

import data.compliance.general.tagging

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
  contains(msg, "[TAG-OPA-1]")
  contains(msg, "Environment")
}
