package terraform.tagging

import rego.v1

import data.terraform.utils

required_tags := {"Environment", "Project"}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.mode == "managed"
  utils.is_create_or_update(resource.change.actions)

  # Directly access tags_all — if the key is absent (non-taggable resource types
  # like aws_s3_bucket_policy omit it entirely from the plan JSON), this expression
  # is undefined and the rule body fails, producing no deny. No blocklist needed.
  tags := resource.change.after.tags_all

  missing := {tag | some tag in required_tags; not tag_present(tags, tag)}
  count(missing) > 0

  msg := sprintf("Resource '%s' is missing required tag(s): %s", [resource.address, concat(", ", missing)])
}

tag_present(tags, key) if {
  value := tags[key]
  value != null
  value != ""
}
