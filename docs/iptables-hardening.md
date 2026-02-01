# Host-Level Egress Hardening with iptables

## Overview

Docker's `internal: true` network setting prevents containers from having a default route to the internet. However, for defense in depth, you may want to add host-level iptables rules to absolutely prevent any bypass.

## Limitations of Docker-Only Isolation

1. **Container escape vulnerabilities**: If an attacker escapes the container, they can access the host network
2. **Docker bugs**: Rare but possible Docker networking bugs could allow bypass
3. **Misconfiguration**: Human error could expose the wrong network

## iptables Rules for Full Enforcement

### Prerequisites

```bash
# Ensure iptables is installed
sudo apt-get install iptables iptables-persistent
```

### Get the Docker Network Subnet

```bash
# Find the agent-net subnet
docker network inspect parachute_agent-net --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
# Example output: 172.20.0.0/16
```

### Apply Blocking Rules

```bash
#!/bin/bash
# parachute-iptables.sh

# Configuration - adjust to your network
AGENT_SUBNET="172.20.0.0/16"  # Get this from docker network inspect
PARACHUTE_IP="172.20.0.2"     # Parachute container IP

# Block all outbound from agent subnet except to Parachute
sudo iptables -I FORWARD -s $AGENT_SUBNET ! -d $PARACHUTE_IP -j DROP
sudo iptables -I FORWARD -s $AGENT_SUBNET -d $PARACHUTE_IP -p tcp --dport 8888 -j ACCEPT
sudo iptables -I FORWARD -s $AGENT_SUBNET -d $PARACHUTE_IP -p tcp --dport 3000 -j ACCEPT

# Log blocked attempts (optional)
sudo iptables -I FORWARD -s $AGENT_SUBNET ! -d $PARACHUTE_IP -j LOG --log-prefix "PARACHUTE_BLOCKED: "

# Make rules persistent
sudo netfilter-persistent save
```

### Verify Rules

```bash
# Test from inside openclaw container
docker exec -it openclaw sh -c "curl https://evil.com"
# Should fail with connection refused

docker exec -it openclaw sh -c "curl -x http://parachute:8888 https://api.anthropic.com"
# Should work (if domain is allowlisted)
```

## Systemd Service for Automatic Rules

Create `/etc/systemd/system/parachute-iptables.service`:

```ini
[Unit]
Description=Parachute iptables rules
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/parachute-iptables.sh
ExecStop=/usr/local/bin/parachute-iptables-remove.sh

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable parachute-iptables
sudo systemctl start parachute-iptables
```

## Cloud Provider Firewalls

For cloud deployments, also configure:

- **AWS**: Security Groups and Network ACLs
- **GCP**: VPC Firewall Rules
- **Azure**: Network Security Groups

These provide an additional layer that persists even if host iptables are modified.

## Verification Checklist

1. [ ] Docker internal network configured
2. [ ] Agent container has no exposed ports
3. [ ] HTTP_PROXY and HTTPS_PROXY set in agent
4. [ ] iptables rules applied (optional but recommended)
5. [ ] Cloud firewall configured (for cloud deployments)
6. [ ] Tested with `curl` from inside agent container
