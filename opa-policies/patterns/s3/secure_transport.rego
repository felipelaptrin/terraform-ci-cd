package terraform.s3

import rego.v1

import data.terraform.utils

deny contains msg if {
  resource := input.resource_changes[_]
  utils.is_resource_of_type(resource, "aws_s3_bucket")

  bucket_name := resource.change.after.bucket
  not has_secure_transport_policy(bucket_name)

  msg := sprintf("S3 bucket '%s' must have an aws_s3_bucket_policy enforcing SecureTransport (HTTPS only)", [bucket_name])
}

has_secure_transport_policy(bucket_name) if {
  policy_resource := input.resource_changes[_]
  utils.is_resource_of_type(policy_resource, "aws_s3_bucket_policy")

  policy_json := policy_resource.change.after.policy
  policy := json.unmarshal(policy_json)

  statement := policy.Statement[_]
  statement.Effect == "Deny"
  statement.Condition.Bool["aws:SecureTransport"] == "false"
}
