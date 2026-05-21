package terraform.regions

import rego.v1

approved_regions := ["us-east-1"]

deny contains msg if {
  provider := input.configuration.provider_config.aws
  region := provider.expressions.region.constant_value
  not region_approved(region)

  msg := sprintf("AWS provider region '%s' is not in the approved list: %s", [region, concat(", ", approved_regions)])
}

region_approved(region) if {
  some r in approved_regions
  r == region
}
