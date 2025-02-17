#!/bin/bash
set -e

echo "Updating Terraform lock file for multiple platforms..."

terraform providers lock \
-platform=windows_amd64 \
-platform=darwin_amd64 \
-platform=linux_amd64 \
-platform=darwin_arm64 \
-platform=linux_arm64

echo "Terraform lock file updated!"
