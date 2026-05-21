package terraform.regions_test

import rego.v1

import data.terraform.regions

test_valid_region if {
  inp := {"configuration": {"provider_config": {"aws": {"expressions": {"region": {"constant_value": "us-east-1"}}}}}}
  count(regions.deny) == 0 with input as inp
}

test_wrong_region if {
  inp := {"configuration": {"provider_config": {"aws": {"expressions": {"region": {"constant_value": "eu-west-1"}}}}}}
  result := regions.deny with input as inp
  count(result) > 0
  some msg in result
  contains(msg, "eu-west-1")
  contains(msg, "not in the approved list")
}
