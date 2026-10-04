# IR Playbook: Command-and-Control Beaconing

**Scenario:** Suspected C2 beacon traffic from an internal host.
**Triggered by rules:** `win_mshta_external_connection.yml`, `win_regsvr32_external_connection.yml`, `win_certutil_download.yml`
**Severity:** High

## Trigger Conditions

- A LOLBin (mshta, regsvr32, rundll32, certutil, WMIC) initiates an outbound TCP connection to an external IP.
- Any process makes periodic connections to the same external IP at regular intervals.
- DNS queries to DGA-looking domains or known-bad infrastructure.
- TLS/SNI mismatch.

## Investigation Steps

### 1. Identify the process and its parent chain
- Pull Sysmon EID 1 for the calling process; determine if it was spawned by an Office app, service, scheduled task, or user shell.
- Verify the calling binary's signature and hash.

### 2. Characterize the network pattern
- Extract all connections from the host in the last 24 hours (Sysmon EID 3).
- Compute inter-arrival times to the same external IP; periodic intervals are indicative of beaconing.
- Check destination ports.

### 3. Threat intelligence enrichment
- Query the destination IP against VT / AbuseIPDB / Shodan.
- Check if the domain resolves to a bulletproof / consumer VPS provider.
- Look for the destination in open-source intel for known C2 frameworks.

### 4. Scope
- Search fleet-wide for the same destination IP or domain in the last 30 days.
- Search fleet-wide for the same process+command line combination.

## Containment

1. Block the destination IP at the egress firewall.
2. Isolate the host if beacon traffic is confirmed.
3. Sinkhole the C2 domain if DNS is under our control.

## Eradication / Recovery

1. Identify persistence mechanisms the beacon installed.
2. Extract the beacon binary from memory if possible.
3. Reimage the host.
4. Rotate any credentials that were used on the host since the first beacon connection.

## Stakeholder Communications

| When | Who | What |
|------|-----|------|
| Immediately | SOC lead | Confirmed beacon, host isolated, C2 blocked |
| Within 1 hour | CISO | Attacker infrastructure IOCs |
| Within 24 hours | All | IOC blocklist distribution |

## Detection Feedback

- If the beacon used a method not caught, add a rule for it.
- If a legitimate service triggers the LOLBin rules, add to the `filter_local` list.
