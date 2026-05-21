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

has_bucket_policy(bucket_name) if {
  bp := input.resource_changes[_]
  bp.type == "aws_s3_bucket_policy"
  is_create_or_update(bp.change.actions)
  bp.change.after.bucket == bucket_name
}

has_secure_transport_deny(policy) if {
  stmt := policy.Statement[_]
  stmt.Effect == "Deny"
  stmt.Condition.Bool["aws:SecureTransport"] == "false"
  stmt.Principal == "*"
  action := stmt.Action
  action == "s3:*"
}
