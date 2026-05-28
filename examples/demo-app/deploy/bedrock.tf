# Provisioned throughput for the Bedrock model the support workflow calls.
# Surfaced by ai-surface as managed AI infrastructure (billing exposure).
resource "aws_bedrock_provisioned_model_throughput" "support_claude" {
  provisioned_model_name = "support-claude-throughput"
  model_units            = 2
  model_arn              = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-20250514-v1:0"
  commitment_duration    = "OneMonth"

  lifecycle {
    prevent_destroy = true
  }
}
