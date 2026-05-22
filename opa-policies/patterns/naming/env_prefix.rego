package compliance.general.naming

import future.keywords.contains
import future.keywords.if

deny contains msg if {
  resource := input.resource_changes[_]
  resource.mode == "managed"
  is_create_or_update(resource.change.actions)

  name := get_resource_name(resource)
  name != null

  tags := object.get(resource.change.after, "tags_all", {})
  env := tags.Environment
  env != null
  env != ""

  prefix := sprintf("%s-", [env])
  not startswith(name, prefix)

  msg := sprintf(
    "[NAME-OPA-1] Resource '%s' name '%s' must start with the environment prefix '%s-'",
    [resource.address, name, env]
  )
}

is_create_or_update(actions) if { actions[_] == "create" }
is_create_or_update(actions) if { actions[_] == "update" }

get_resource_name(resource) := resource.change.after.bucket if {
  resource.type == "aws_s3_bucket"
}

get_resource_name(resource) := resource.change.after.name if {
  resource.type != "aws_s3_bucket"
}
