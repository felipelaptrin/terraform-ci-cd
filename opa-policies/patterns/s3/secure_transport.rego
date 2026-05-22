package compliance.amazon_s3.ssl

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Deny: S3 bucket policy missing SecureTransport deny statement
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_policy"
  is_create_or_update(resource.change.actions)

  policy_value := resource.change.after.policy
  policy := json.unmarshal(policy_value)

  not has_secure_transport_deny(policy)

  msg := sprintf(
    "[S3-OPA-1] Resource '%s' does not enforce SSL/TLS. Bucket policy must include a Deny statement with Condition Bool aws:SecureTransport set to \"false\".",
    [resource.address]
  )
}

# Deny: S3 bucket created without any corresponding bucket policy
deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  is_create_or_update(resource.change.actions)

  bucket_name := resource.change.after.bucket
  not has_bucket_policy(bucket_name)

  msg := sprintf(
    "[S3-OPA-1] Resource '%s' (bucket '%s') has no bucket policy. A bucket policy with a Deny statement for aws:SecureTransport \"false\" is required.",
    [resource.address, bucket_name]
  )
}

is_create_or_update(actions) if { actions[_] == "create" }
is_create_or_update(actions) if { actions[_] == "update" }

# Match by bucket name when the field is known at plan time
has_bucket_policy(bucket_name) if {
  bucket_policy := input.resource_changes[_]
  bucket_policy.type == "aws_s3_bucket_policy"
  is_create_or_update(bucket_policy.change.actions)
  bucket_policy.change.after.bucket == bucket_name
}

# Match when bucket field is null (computed, unknown at plan time for new resources)
has_bucket_policy(_) if {
  bucket_policy := input.resource_changes[_]
  bucket_policy.type == "aws_s3_bucket_policy"
  is_create_or_update(bucket_policy.change.actions)
  bucket_policy.change.after.bucket == null
}

has_secure_transport_deny(policy) if {
  statement := policy.Statement[_]
  statement.Effect == "Deny"
  statement.Condition.Bool["aws:SecureTransport"] == "false"
  statement.Principal == "*"
  statement.Action == "s3:*"
}
