package terraform.utils

import rego.v1

is_create_or_update(actions) if {
  actions[count(actions) - 1] == "create"
}

is_create_or_update(actions) if {
  actions[count(actions) - 1] == "update"
}

is_resource_of_type(resource, type) if {
  resource.mode == "managed"
  resource.type == type
  is_create_or_update(resource.change.actions)
}

get_resource_name(resource) := name if {
  resource.type == "aws_s3_bucket"
  name := resource.change.after.bucket
}

get_resource_name(resource) := name if {
  resource.type != "aws_s3_bucket"
  name := resource.change.after.name
}
