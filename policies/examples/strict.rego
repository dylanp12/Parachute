package parachute

# Strict policy example
# Blocks all write operations and requires approval for everything else.

default decision = "pending"

# Allow only read-only commands
decision = "allow" {
    read_only_commands := {"ls", "cat", "head", "tail", "grep", "find", "echo", "pwd", "whoami", "date", "env"}
    cmd_parts := split(input.command, " ")
    read_only_commands[cmd_parts[0]]
}

# Block all destructive operations
decision = "block" {
    contains(input.command, "rm -rf /")
}

decision = "block" {
    contains(input.command, ":(){ :|:& };:")
}

decision = "block" {
    regex.match(`\bmkfs\b`, input.command)
}

decision = "block" {
    regex.match(`\bdd\b.*of=/dev/`, input.command)
}

# Block network tools
decision = "block" {
    regex.match(`\b(nc|netcat|ncat)\b`, input.command)
}

reason = "blocked by strict policy" { decision == "block" }
reason = "requires approval in strict mode" { decision == "pending" }
reason = "" { decision == "allow" }
