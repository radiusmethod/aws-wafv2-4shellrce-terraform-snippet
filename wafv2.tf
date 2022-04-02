...
  rule {
    name     = "Log4RCE"
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
          name = "PROPFIND_METHOD"
        }

        excluded_rule {
          name = "ExploitablePaths_URIPATH"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "Log4RCE"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "Log4RCE-Block"
    priority = ?

    action {
      block {}
    }
    
    statement {
      or_statement {
        statement {
          label_match_statement {
            scope = "LABEL"
            key   = "awswaf:managed:aws:known-bad-inputs:Log4JRCE"
          }
        }

        statement {
          label_match_statement {
            scope = "LABEL"
            key   = "awswaf:managed:aws:known-bad-inputs:JavaDeserializationRCE_HEADER"
          }
        }

        statement {
          label_match_statement {
            scope = "LABEL"
            key   = "awswaf:managed:aws:known-bad-inputs:JavaDeserializationRCE_BODY"
          }
        }

        statement {
          label_match_statement {
            scope = "LABEL"
            key   = "awswaf:managed:aws:known-bad-inputs:JavaDeserializationRCE_URIPATH"
          }
        }

        statement {
          label_match_statement {
            scope = "LABEL"
            key   = "awswaf:managed:aws:known-bad-inputs:JavaDeserializationRCE_QUERYSTRING"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "Log4RCE-blocking"
      sampled_requests_enabled   = true
    }
  }
...
