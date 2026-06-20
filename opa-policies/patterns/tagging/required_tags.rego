package compliance.general.tagging

import future.keywords.contains
import future.keywords.if
import future.keywords.in

required_tags := {"Environment", "Project"}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.mode == "managed"
  is_create_or_update(resource.change.actions)

  tags := resource.change.after.tags_all

  missing := {tag | some tag in required_tags; not tag_present(tags, tag)}
  count(missing) > 0

  msg := sprintf(
    "[TAG-OPA-1] Resource '%s' is missing required tag(s): %s",
    [resource.address, concat(", ", missing)]
  )
}

is_create_or_update(actions) if { actions[_] == "create" }
is_create_or_update(actions) if { actions[_] == "update" }

tag_present(tags, key) if {
  value := tags[key]
  value != null
  value != ""
}
