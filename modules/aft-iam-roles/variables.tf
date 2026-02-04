variable "spacelift_account_name" {
  description = "Spacelift account name for external ID pattern matching. Required when using default external ID pattern."
  type        = string
  default     = ""
}

variable "spacelift_api_endpoint" {
  description = "Spacelift API endpoint. Leave blank to use the default Spacelift API endpoint"
  type        = string
  default     = ""
}

variable "spacelift_enabled" {
  description = "Set to true to enable Spacelift integration"
  type        = bool
  default     = false
}