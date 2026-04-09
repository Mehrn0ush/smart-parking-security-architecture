package smartparking.edge

default allow = false

# Example policy:
# allow a gateway to issue only approved actions for its assigned gate.
allow if {
    input.subject.type == "gateway"
    input.subject.status == "active"
    input.action == "gate.open"
    input.resource.type == "gate"
    input.resource.id == input.subject.assigned_gate
    input.environment.command_signed == true
    input.environment.replay_check_passed == true
}

