resource "aws_bedrock_provisioned_model_throughput" "claude_throughput" {
  provisioned_model_name = "claude-prod-throughput"
  model_units            = 1
  model_arn              = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0"
  commitment_duration    = "OneMonth"
}
