...
  rule {
    name     = "Log4JRCE"
    priority = ?

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"

        excluded_rule {
          name = "Host_localhost_HEADER"
        }

        excluded_rule {
          name = "NoUserAgent_HEADER"
        }

        excluded_rule {
          name = "ExploitablePaths_URIPATH"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "Log4JRCE"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "Log4JRCE-Block"
    priority = ?

    action {
      block {}
    }

    statement {
      label_match_statement {
        scope = "LABEL"
        key   = "awswaf:managed:aws:known-bad-inputs:Log4JRCE"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "Log4JRCE-blocking"
      sampled_requests_enabled   = true
    }
  }
...
