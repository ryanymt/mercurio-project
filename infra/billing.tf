# An optional monthly budget on the project, made only when billing_account and monthly_budget_usd
# are both set. Its API is reachable with user credentials because main.tf sends the quota to the
# project (billing_project, user_project_override).

locals {
  budget = var.billing_account != null && var.monthly_budget_usd != null
}

resource "google_billing_budget" "monthly" {
  count           = local.budget ? 1 : 0
  billing_account = var.billing_account
  display_name    = "${var.project_id} monthly"

  budget_filter {
    projects               = ["projects/${var.project_number}"]
    calendar_period        = "MONTH"
    credit_types_treatment = "INCLUDE_ALL_CREDITS"
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(floor(var.monthly_budget_usd))
    }
  }

  threshold_rules {
    threshold_percent = 0.5
    spend_basis       = "CURRENT_SPEND"
  }
  threshold_rules {
    threshold_percent = 0.9
    spend_basis       = "CURRENT_SPEND"
  }
  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "CURRENT_SPEND"
  }
}
