package terraform.tagging

import rego.v1

import data.terraform.utils

required_tags := {"Environment", "Project"}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.mode == "managed"
  utils.is_create_or_update(resource.change.actions)

  tags := object.get(resource.change.after, "tags_all", {})
  missing := {tag | some tag in required_tags; not tag_present(tags, tag)}
  count(missing) > 0

  msg := sprintf("Resource '%s' is missing required tag(s): %s", [resource.address, concat(", ", missing)])
}

tag_present(tags, key) if {
  value := tags[key]
  value != null
  value != ""
}
