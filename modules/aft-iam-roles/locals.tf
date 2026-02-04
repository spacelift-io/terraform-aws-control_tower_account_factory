# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

locals {
  aft_admin_assumed_role_arn = "arn:${data.aws_partition.current.partition}:sts::${data.aws_caller_identity.aft_management.account_id}:assumed-role/AWSAFTAdmin/AWSAFT-Session"

  spacelift_principal_account_id  = can(regex("us\\..*spacelift\\.io", var.spacelift_api_endpoint)) ? "577638371743" : "324880187172"
  spacelift_trust_statement = jsonencode({
    Effect = "Allow"
    Principal = {
      AWS = "arn:${data.aws_partition.current.partition}:iam::${local.spacelift_principal_account_id}:root"
    }
    Action = "sts:AssumeRole"
    Condition = {
      StringLike = {
        "sts:ExternalId" = "${var.spacelift_account_name}@*"
      }
    }
  })
}
