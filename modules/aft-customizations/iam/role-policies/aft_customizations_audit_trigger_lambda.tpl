{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": [
        "arn:${data_aws_partition_current_partition}:ssm:${data_aws_region_current_name}:${data_aws_caller_identity_current_account_id}:parameter/aft/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem"
      ],
      "Resource": [
        "${aft_customizations_audit_table_arn}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:GenerateDataKey*",
        "kms:Encrypt",
        "kms:Decrypt"
      ],
      "Resource": [
        "${aws_kms_key_aft_arn}"
      ]
    }
  ]
}
