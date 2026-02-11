package parachute

# Default Parachute policy (Rego)
# This policy mirrors the default regex-based behavior.
# Customize by modifying rules or adding new .rego files.

default decision = "allow"

# Block destructive commands
decision = "block" {
    contains(input.command, "rm -rf /")
}

decision = "block" {
    contains(input.command, ":(){ :|:& };:")
}

decision = "block" {
    startswith(input.command, "mkfs.")
}

# Require approval for risky commands
decision = "pending" {
    regex.match(`\brm\b`, input.command)
    not decision == "block"
}

decision = "pending" {
    regex.match(`\bsudo\b`, input.command)
    not decision == "block"
}

decision = "pending" {
    regex.match(`\bgit\b.*(push|force)`, input.command)
    not decision == "block"
}

# Output the reason
reason = "destructive command blocked" { decision == "block" }
reason = "command requires approval" { decision == "pending" }
reason = "" { decision == "allow" }
