# Copyright Amazon.com, Inc. or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
locals {
  lambda_managed_policies = [data.aws_iam_policy.AWSLambdaBasicExecutionRole.arn, data.aws_iam_policy.AWSLambdaVPCAccessExecutionRole.arn]
  provision_oss           = (var.terraform_distribution == "oss" || var.terraform_distribution == "tofu") ? true : false
  provision_spacelift     = var.terraform_distribution == "spacelift" ? true : false
}
