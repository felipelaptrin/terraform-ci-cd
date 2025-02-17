# src

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.10.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 5.86 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.87.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_bucket-test"></a> [bucket-test](#module\_bucket-test) | ../modules/bucket | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_kms_key.s3](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_ami.ubuntu](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | Region to deploy the resources | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_ami"></a> [ami](#output\_ami) | n/a |
<!-- END_TF_DOCS -->
