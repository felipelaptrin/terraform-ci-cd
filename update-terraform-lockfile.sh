#!/bin/bash
set -e

echo "Updating Terraform lock file for multiple platforms..."

cd src/

terraform providers lock \
-platform=linux_amd64 \
-platform=darwin_arm64

echo "Terraform lock file updated!"
