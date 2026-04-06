const isClosed = (portsMap, port) => portsMap.get(port)?.open === false;
const isOpen = (portsMap, port) => portsMap.get(port)?.open === true;

const buildIssueSummary = (rule) => {
  if (rule === 'icmp_likely_filtered') {
    return {
      issue: 'ICMP likely filtered on public IP',
      explanation: 'Ping failed and all tested ports are closed, which is common when public-facing firewalls drop ICMP and unsolicited inbound traffic.',
      context: 'This does not automatically mean outage. Many providers and edge firewalls intentionally block ping on WAN addresses.',
      cause: 'ICMP filtering and closed inbound policy on the public edge.',
      solution: 'Validate reachability using allowed management channels (VPN, Winbox allowlist, HTTPS) and confirm firewall policy intent.',
      suggestedChecks: [
        'Verify whether ICMP is intentionally blocked in input chain',
        'Check if inbound policy is default-drop for non-whitelisted sources',
      ],
    };
  }

  if (rule === 'device_unreachable') {
    return {
      issue: 'Device unreachable',
      explanation: 'Ping failed and traffic pattern does not clearly indicate only ICMP filtering.',
      context: 'Could indicate WAN outage, device down, route issue, or strict edge ACLs.',
      cause: 'Possible connectivity outage or routing/filtering issue.',
      solution: 'Verify WAN status, power, upstream route, and edge firewall policy from another known-good source.',
      suggestedChecks: [
        'Check WAN interface state and errors',
        'Validate default route and gateway reachability',
      ],
    };
  }

  if (rule === 'dns_not_applicable') {
    return {
      issue: 'DNS check not applicable for IP target',
      explanation: 'Target is a direct IP address, so DNS resolution is not required for this test.',
      context: 'DNS failure status should not be treated as an incident indicator for direct IP diagnostics.',
      cause: 'No DNS lookup required for IP-based diagnostic.',
      solution: 'Continue analyzing ping/port results. Use hostname target if DNS validation is needed.',
      suggestedChecks: ['If needed, rerun with a hostname to validate DNS path.'],
    };
  }

  if (rule === 'dns_failure') {
    return {
      issue: 'DNS resolution failure',
      explanation: 'Hostname could not be resolved by DNS.',
      context: 'Common in misconfigured DNS resolvers, blocked UDP/53 traffic, or stale DNS settings.',
      cause: 'DNS resolver configuration or upstream DNS reachability issue.',
      solution: 'Check DNS server settings and resolver connectivity on router and upstream network.',
      suggestedChecks: ['Inspect /ip dns print', 'Verify DNS server reachability from router'],
    };
  }

  if (rule === 'sip_port_5060_blocked') {
    return {
      issue: 'SIP signaling appears blocked',
      explanation: 'Host is reachable but port 5060 is closed.',
      context: 'For VoIP incidents, this often indicates firewall/NAT policy preventing SIP signaling.',
      cause: 'Firewall/NAT policy blocking SIP port 5060.',
      solution: 'Allow/open port 5060 as required by architecture and confirm SIP NAT/filter rules.',
      suggestedChecks: ['Review filter rules for dst-port=5060', 'Review NAT mapping for SIP service'],
    };
  }

  if (rule === 'winbox_blocked') {
    return {
      issue: 'Winbox management access blocked',
      explanation: 'Port 8291 is closed while web ports are reachable.',
      context: 'This can be intentional hardening, or a misconfigured management ACL for remote support.',
      cause: 'Management firewall policy blocking Winbox.',
      solution: 'Review input chain allowlist for trusted support IPs and management ports.',
      suggestedChecks: ['Inspect input rules for tcp/8291', 'Check address-list used for management access'],
    };
  }

  if (rule === 'all_ports_closed') {
    return {
      issue: 'No exposed services detected',
      explanation: 'All tested ports are closed from the probing source.',
      context: 'This can mean either strict firewall policy (expected) or unintended inbound blocking.',
      cause: 'No exposed services or firewall blocking incoming traffic.',
      solution: 'Confirm expected exposure policy and verify firewall/NAT rules for required services.',
      suggestedChecks: ['Review firewall drop counters', 'Confirm required services are bound/listening internally'],
    };
  }

  return {
    issue: 'No critical WAN-side fault detected',
    explanation: 'Baseline ping, DNS (if applicable), and key port checks do not show a critical external failure.',
    context: 'Issue may be at application/session/media level rather than basic network reachability.',
    cause: 'No clear WAN-side fault from current probes.',
    solution: 'Proceed with deeper VoIP checks (registration, RTP path, codec, QoS).',
    suggestedChecks: ['Inspect SIP registration logs', 'Validate RTP flow and packet loss/jitter'],
  };
};

const buildAnalysis = ({ target, ping, dns, portCheck, dnsWasRequired }) => {
  const findings = [];
  const portsMap = new Map(portCheck.ports.map((item) => [item.port, item]));
  const allPortsClosed = portCheck.ports.length > 0 && portCheck.ports.every((port) => !port.open);

  if (!ping.ok && allPortsClosed) {
    findings.push({
      rule: 'icmp_likely_filtered',
      probableCause: 'Ping blocked and inbound ports closed from probe source; likely WAN edge filtering policy.',
      recommendedAction: 'Treat as potentially expected hardening. Validate with allowed management path and ACL review.',
      mikrotikChecks: [
        'Check input chain policy in /ip firewall filter print',
        'Validate support source IP allowlist for management',
      ],
      routerOsCommand: '/ip firewall filter print; /ip firewall address-list print',
    });
  } else if (!ping.ok) {
    findings.push({
      rule: 'device_unreachable',
      probableCause: 'Ping failed and host may be unreachable due to outage/routing/filtering.',
      recommendedAction: 'Verify WAN state, upstream route, and edge ACL from multiple probe points.',
      mikrotikChecks: [
        'Check WAN interface status and counters',
        'Check default route and gateway health',
      ],
      routerOsCommand: '/interface print; /ip route print where dst-address=0.0.0.0/0',
    });
  }

  if (!dnsWasRequired) {
    findings.push({
      rule: 'dns_not_applicable',
      probableCause: 'DNS check is not applicable for direct IP targets.',
      recommendedAction: 'Use hostname target when DNS validation is required.',
      mikrotikChecks: ['Optional: verify resolver config if hostname-based incidents are suspected.'],
      routerOsCommand: '/ip dns print',
    });
  } else if (!dns.ok) {
    findings.push({
      rule: 'dns_failure',
      probableCause: 'Hostname resolution failed via DNS.',
      recommendedAction: 'Validate DNS resolvers and outbound access to DNS servers.',
      mikrotikChecks: [
        'Inspect DNS settings in /ip dns print',
        'Ping configured resolver addresses',
      ],
      routerOsCommand: '/ip dns print; /ping 8.8.8.8 count=4',
    });
  }

  if (ping.ok && isClosed(portsMap, 5060)) {
    findings.push({
      rule: 'sip_port_5060_blocked',
      probableCause: 'Port 5060 closed while host remains reachable.',
      recommendedAction: 'Review SIP firewall/NAT exposure policy.',
      mikrotikChecks: ['Check filter rules for dst-port=5060', 'Check NAT entries for SIP service'],
      routerOsCommand: '/ip firewall filter print; /ip firewall nat print',
    });
  }

  if (isClosed(portsMap, 8291) && (isOpen(portsMap, 80) || isOpen(portsMap, 443))) {
    findings.push({
      rule: 'winbox_blocked',
      probableCause: 'Winbox blocked while HTTP/HTTPS still reachable.',
      recommendedAction: 'Verify management ACL/allowlist for remote support.',
      mikrotikChecks: ['Inspect input chain rules for tcp/8291'],
      routerOsCommand: '/ip firewall filter print where chain=input',
    });
  }

  if (allPortsClosed) {
    findings.push({
      rule: 'all_ports_closed',
      probableCause: 'All tested inbound ports are closed from this source.',
      recommendedAction: 'Confirm whether this is expected security posture or unintended blocking.',
      mikrotikChecks: ['Review firewall counters and policies', 'Check service exposure requirements'],
      routerOsCommand: '/ip firewall filter print stats',
    });
  }

  if (findings.length === 0) {
    findings.push({
      rule: 'no_critical_issue_detected',
      probableCause: 'No critical WAN-side fault detected from current checks.',
      recommendedAction: 'Continue with deeper VoIP-layer diagnostics.',
      mikrotikChecks: ['Check SIP registration and RTP path telemetry'],
      routerOsCommand: '/log print where message~"sip"',
    });
  }

  const primaryFinding = findings[0];
  const summary = buildIssueSummary(primaryFinding.rule);

  return {
    issue: summary.issue,
    explanation: summary.explanation,
    context: summary.context,
    cause: summary.cause,
    solution: summary.solution,
    suggestedChecks: summary.suggestedChecks,
    overallStatus: primaryFinding.rule === 'no_critical_issue_detected' ? 'healthy' : 'attention_required',
    primaryFinding,
    findings,
    target,
  };
};

module.exports = {
  buildAnalysis,
};