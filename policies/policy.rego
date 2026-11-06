
package sailpoint.access

import rego.v1

default allow := false
default require_manual_approval := false
default reason := "Denied by OPA: User department is not authorized for this resource."

# Rule 1: Auto-Approve if user is in an allowed department AND has completed security training
allow if {
    input.user_department in data.allowed_departments
    input.security_training == "true"
}

# Rule 2: Route to Manager Approval if user is in an allowed department, but training is false
require_manual_approval if {
    input.user_department in data.allowed_departments
    input.security_training != "true"
}

reason := "Auto-Approved by OPA (via OPAL): Department and Security Training verified." if {
    allow == true
}

reason := "Manual Approval Required: User is in an authorized department, but Security Training is incomplete." if {
    require_manual_approval == true
    allow == false
}
