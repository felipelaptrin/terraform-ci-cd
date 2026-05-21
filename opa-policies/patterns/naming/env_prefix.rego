package terraform.naming

import rego.v1

import data.terraform.utils

deny contains msg if {
  resource := input.resource_changes[_]
  resource.mode == "managed"
  utils.is_create_or_update(resource.change.actions)

  name := utils.get_resource_name(resource)
  name != null

  tags := object.get(resource.change.after, "tags_all", {})
  env := tags.Environment
  env != null
  env != ""

  prefix := sprintf("%s-", [env])
  not startswith(name, prefix)

  msg := sprintf("Resource '%s' name '%s' must start with the environment prefix '%s-'", [resource.address, name, env])
}
