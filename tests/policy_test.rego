
package sailpoint.access

import rego.v1

test_auto_approve_secops_trained if {
    allow with input as {"user_department": "SecOps", "security_training": "true"}
        with data.allowed_departments as ["SecOps", "CloudSecurity"]
}

test_manual_approval_secops_untrained if {
    require_manual_approval with input as {"user_department": "SecOps", "security_training": "false"}
        with data.allowed_departments as ["SecOps", "CloudSecurity"]
}

test_deny_unauthorized_department if {
    not allow with input as {"user_department": "Marketing", "security_training": "true"}
        with data.allowed_departments as ["SecOps", "CloudSecurity"]
    not require_manual_approval with input as {"user_department": "Marketing", "security_training": "true"}
        with data.allowed_departments as ["SecOps", "CloudSecurity"]
}
