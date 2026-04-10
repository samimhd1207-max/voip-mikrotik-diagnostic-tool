const isClosed = (portsMap, port) => portsMap.get(port)?.open === false;
const isOpen = (portsMap, port) => portsMap.get(port)?.open === true;
const looksVoipRelatedTarget = (target) => /\b(sip|voip|pbx|asterisk|trunk|softswitch)\b/i.test(target);

const allowSip5060Command =
  '/ip firewall filter add chain=forward protocol=udp dst-port=5060 action=accept comment="Allow SIP"';

const addSipDstNatCommand =
  '/ip firewall nat add chain=dstnat protocol=udp dst-port=5060 action=dst-nat to-addresses=192.168.88.10';
const addRtpDstNatCommand =
  '/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-port=10000-20000 to-addresses=192.168.88.10 to-ports=10000-20000 comment="RTP dst-nat 10000-20000"';
const addSrcNatCommand =
  '/ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment="VoIP src-nat"';
const allowRtpCommand =
  '/ip firewall filter add chain=forward protocol=udp dst-port=10000-20000 action=accept comment="Allow RTP"';
const restrictWinboxCommand =
  '/ip service set winbox address=192.168.0.0/24';
const disableTelnetCommand =
  '/ip service disable telnet';
const disableFtpCommand =
  '/ip service disable ftp';
const openSipFirewallCommand =
  '/ip firewall filter add chain=forward protocol=udp dst-port=5060 action=accept comment="Allow SIP signaling"';

const buildNoActionPayload = (target) => ({
  issue: 'Healthy baseline with hardening opportunities',
  explanation: 'Core connectivity checks are healthy, with no outage signature detected.',
  context: 'Even healthy systems should reduce attack surface and restrict management exposure.',
  cause: 'No critical service failure detected, but security posture can be improved.',
  solution: 'Restrict management plane and disable unused legacy services.',
  mikrotikCommands: [restrictWinboxCommand, disableTelnetCommand, disableFtpCommand],
  overallStatus: 'healthy',
  confidence: 35,
  confidenceScore: 35,
  primaryFinding: {
    rule: 'no_action_required',
    probableCause: 'System is healthy but security can be improved by restricting open ports.',
    recommendedAction: 'Apply management restrictions and disable legacy plaintext services.',
    mikrotikChecks: ['No outage detected in ping/DNS/port baselines.', 'Hardening actions are recommended.'],
    routerOsCommand: restrictWinboxCommand,
    routerOsCommands: [restrictWinboxCommand, disableTelnetCommand, disableFtpCommand],
    confidence: 35,
    confidenceScore: 35,
  },
  findings: [
    {
      rule: 'no_action_required',
      probableCause: 'System is healthy but security can be improved by restricting open ports.',
      recommendedAction: 'Apply management restrictions and disable legacy plaintext services.',
      evidence: ['No critical failure detected; optimization/hardening path identified.'],
      routerOsCommands: [restrictWinboxCommand, disableTelnetCommand, disableFtpCommand],
      confidence: 35,
      confidenceScore: 35,
    },
  ],
  target,
});

const buildAnalysis = ({ target, ping, portCheck, expectsSipService = false, mikrotikSnapshot = null }) => {
  const ports = Array.isArray(portCheck?.ports) ? portCheck.ports : [];
  const portsMap = new Map(ports.map((item) => [item.port, item]));
  const sipExpected = expectsSipService || looksVoipRelatedTarget(target);

  if (!sipExpected || !mikrotikSnapshot?.enabled || ping?.ok !== true) {
    return buildNoActionPayload(target);
  }

  const sipPortBlocked = isClosed(portsMap, 5060);
  const sipPortOpen = portsMap.get(5060)?.open === true;
  const firewallBlocksSip = Boolean(mikrotikSnapshot?.analysis?.firewall?.blocked);
  const firewallHasRtpAllow = Boolean(mikrotikSnapshot?.analysis?.firewall?.hasRtpAllowRule);
  const firewallHasRtpBlock = Boolean(mikrotikSnapshot?.analysis?.firewall?.hasRtpBlockRule);
  const hasSipDstNat = Boolean(mikrotikSnapshot?.analysis?.nat?.hasSipDstNat);
  const hasRtpDstNat = Boolean(mikrotikSnapshot?.analysis?.nat?.hasRtpDstNat);
  const hasSrcNat = Boolean(mikrotikSnapshot?.analysis?.nat?.hasSrcNat);

  const testedRtpPorts = ports.filter((item) => item.port >= 10000 && item.port <= 20000);
  const noRtpPortOpen = testedRtpPorts.length > 0 && testedRtpPorts.every((item) => item.open === false);
  const insecurePorts = [21, 23, 25, 110].filter((port) => isOpen(portsMap, port));

  if (insecurePorts.length > 0) {
    return {
      issue: 'Insecure services exposed',
      explanation: `Insecure plaintext services are reachable: ${insecurePorts.join(', ')}.`,
      context: 'Legacy protocols expose credentials and metadata to interception risks.',
      cause: 'Unsecured protocols are open on the network.',
      solution: 'Disable or strictly restrict insecure services and migrate to secure alternatives.',
      mikrotikCommands: [disableTelnetCommand, disableFtpCommand],
      overallStatus: 'attention_required',
      confidence: 94,
      confidenceScore: 94,
      primaryFinding: {
        rule: 'insecure_services_exposed',
        probableCause: 'Unsecured protocols are open on the network.',
        recommendedAction: 'Disable FTP/Telnet and restrict SMTP/POP3 to trusted sources only.',
        mikrotikChecks: [`Open insecure ports detected: ${insecurePorts.join(', ')}`],
        routerOsCommand: disableTelnetCommand,
        routerOsCommands: [disableTelnetCommand, disableFtpCommand],
        confidence: 94,
        confidenceScore: 94,
      },
      findings: [
        {
          rule: 'insecure_services_exposed',
          probableCause: 'Unsecured protocols are open on the network.',
          recommendedAction: 'Disable FTP/Telnet and restrict SMTP/POP3 to trusted sources only.',
          evidence: [`Detected open insecure ports: ${insecurePorts.join(', ')}.`],
          routerOsCommands: [disableTelnetCommand, disableFtpCommand],
          confidence: 94,
          confidenceScore: 94,
        },
      ],
      target,
    };
  }

  if (isOpen(portsMap, 8291)) {
    return {
      issue: 'Winbox management port exposed',
      explanation: 'Winbox port 8291 is reachable from the probe source.',
      context: 'If this probe source is WAN or untrusted segment, this is a management-plane exposure.',
      cause: 'MikroTik management access is broadly reachable.',
      solution: 'Restrict Winbox access to trusted management subnet(s).',
      mikrotikCommands: [restrictWinboxCommand],
      overallStatus: 'attention_required',
      confidence: 88,
      confidenceScore: 88,
      primaryFinding: {
        rule: 'winbox_exposed',
        probableCause: 'MikroTik management access is broadly reachable.',
        recommendedAction: 'Restrict Winbox by source subnet/IP allowlist.',
        mikrotikChecks: ['Port 8291 reachable from probe source.'],
        routerOsCommand: restrictWinboxCommand,
        routerOsCommands: [restrictWinboxCommand],
        confidence: 88,
        confidenceScore: 88,
      },
      findings: [
        {
          rule: 'winbox_exposed',
          probableCause: 'MikroTik management access is broadly reachable.',
          recommendedAction: 'Restrict Winbox by source subnet/IP allowlist.',
          evidence: ['Port 8291 open on target.'],
          routerOsCommands: [restrictWinboxCommand],
          confidence: 88,
          confidenceScore: 88,
        },
      ],
      target,
    };
  }

  if (expectsSipService && sipPortBlocked) {
    return {
      issue: 'SIP signaling unreachable while expected',
      explanation: 'SIP service is expected but UDP 5060 is closed from the probe source.',
      context: 'Inbound registration/call setup can fail when signaling cannot reach PBX edge.',
      cause: 'Firewall does not allow SIP signaling path.',
      solution: 'Open SIP signaling rule for UDP 5060 in forward path.',
      mikrotikCommands: [openSipFirewallCommand],
      overallStatus: 'attention_required',
      confidence: 90,
      confidenceScore: 90,
      primaryFinding: {
        rule: 'sip_expected_but_closed',
        probableCause: 'Firewall blocks expected SIP signaling.',
        recommendedAction: 'Add explicit allow rule for UDP 5060.',
        mikrotikChecks: ['expectsSipService=true and port 5060 observed closed.'],
        routerOsCommand: openSipFirewallCommand,
        routerOsCommands: [openSipFirewallCommand],
        confidence: 90,
        confidenceScore: 90,
      },
      findings: [
        {
          rule: 'sip_expected_but_closed',
          probableCause: 'Firewall blocks expected SIP signaling.',
          recommendedAction: 'Add explicit allow rule for UDP 5060.',
          evidence: ['SIP expected by input contract, but port 5060 is closed.'],
          routerOsCommands: [openSipFirewallCommand],
          confidence: 90,
          confidenceScore: 90,
        },
      ],
      target,
    };
  }

  if (sipPortBlocked && firewallBlocksSip) {
    return {
      issue: 'SIP 5060 blocked by MikroTik firewall',
      explanation: 'Port 5060 is closed from probe and MikroTik filter shows a matching block condition.',
      context: 'Signaling is being dropped before reaching PBX/trunk endpoint.',
      cause: 'Firewall forward/input policy blocks UDP 5060.',
      solution: 'Add explicit allow rule for UDP 5060 before drop rules.',
      mikrotikCommands: [allowSip5060Command],
      overallStatus: 'attention_required',
      confidence: 96,
      confidenceScore: 98,
      primaryFinding: {
        rule: 'sip_5060_blocked_firewall',
        probableCause: 'Firewall policy blocks SIP UDP 5060.',
        recommendedAction: 'Allow UDP 5060 in forward chain before drop.',
        mikrotikChecks: ['Port 5060 closed externally + firewall block detected in MikroTik snapshot.'],
        routerOsCommand: allowSip5060Command,
        routerOsCommands: [allowSip5060Command],
        confidence: 96,
        confidenceScore: 98,
      },
      findings: [
        {
          rule: 'sip_5060_blocked_firewall',
          probableCause: 'Firewall policy blocks SIP UDP 5060.',
          recommendedAction: 'Allow UDP 5060 in forward chain before drop.',
          evidence: ['Port 5060 closed externally + firewall block detected in MikroTik snapshot.'],
          routerOsCommands: [allowSip5060Command],
          confidence: 96,
          confidenceScore: 98,
        },
      ],
      target,
    };
  }

  if (!hasSipDstNat) {
    return {
      issue: 'Missing SIP dst-nat rule',
      explanation: 'MikroTik NAT table does not include dst-nat for SIP 5060.',
      context: 'Inbound SIP signaling may hit WAN but is not forwarded to PBX.',
      cause: 'No dst-nat translation for UDP 5060.',
      solution: 'Add dst-nat for UDP 5060 to PBX.',
      mikrotikCommands: [addSipDstNatCommand],
      overallStatus: 'attention_required',
      confidence: 88,
      confidenceScore: 95,
      primaryFinding: {
        rule: 'sip_dstnat_missing',
        probableCause: 'Missing dst-nat for SIP UDP 5060.',
        recommendedAction: 'Create dst-nat rule for UDP 5060.',
        mikrotikChecks: ['No SIP dst-nat rule found in MikroTik NAT snapshot.'],
        routerOsCommand: addSipDstNatCommand,
        routerOsCommands: [addSipDstNatCommand],
        confidence: 88,
        confidenceScore: 95,
      },
      findings: [
        {
          rule: 'sip_dstnat_missing',
          probableCause: 'Missing dst-nat for SIP UDP 5060.',
          recommendedAction: 'Create dst-nat rule for UDP 5060.',
          evidence: ['No SIP dst-nat rule found in MikroTik NAT snapshot.'],
          routerOsCommands: [addSipDstNatCommand],
          confidence: 88,
          confidenceScore: 95,
        },
      ],
      target,
    };
  }

  if (sipPortOpen && (noRtpPortOpen || firewallHasRtpBlock || !firewallHasRtpAllow)) {
    return {
      issue: 'Possible one-way audio (RTP blocked)',
      explanation: 'SIP signaling is reachable but RTP media path is blocked or not allowed.',
      context: 'Calls may establish successfully while audio is one-way or absent.',
      cause: firewallHasRtpBlock
        ? 'MikroTik firewall contains a drop/reject rule for UDP 10000-20000.'
        : noRtpPortOpen
        ? 'RTP ports (10000-20000) tested as closed while SIP 5060 is open.'
        : 'MikroTik firewall does not show an allow rule for UDP 10000-20000.',
      solution: 'Allow RTP UDP 10000-20000 in forward chain and verify media flow.',
      mikrotikCommands: [allowRtpCommand],
      overallStatus: 'attention_required',
      confidence: 84,
      confidenceScore: 84,
      primaryFinding: {
        rule: 'possible_one_way_audio_rtp_blocked',
        probableCause: 'Possible one-way audio (RTP blocked)',
        recommendedAction: 'Allow UDP 10000-20000 and re-test bidirectional audio.',
        mikrotikChecks: [
          `firewallHasRtpAllow=${firewallHasRtpAllow}`,
          `firewallHasRtpBlock=${firewallHasRtpBlock}`,
          `hasRtpDstNat=${hasRtpDstNat}`,
          `hasSrcNat=${hasSrcNat}`,
          `rtpPortsTested=${testedRtpPorts.length}`,
          `rtpAllClosed=${noRtpPortOpen}`,
        ],
        routerOsCommand: allowRtpCommand,
        routerOsCommands: [allowRtpCommand],
        confidence: 84,
        confidenceScore: 84,
      },
      findings: [
        {
          rule: 'possible_one_way_audio_rtp_blocked',
          probableCause: 'Possible one-way audio (RTP blocked)',
          recommendedAction: 'Allow UDP 10000-20000 and re-test bidirectional audio.',
          evidence: [
            'SIP 5060 is open/reachable.',
            `MikroTik firewall state: hasRtpAllowRule=${firewallHasRtpAllow}, hasRtpBlockRule=${firewallHasRtpBlock}.`,
            ...(testedRtpPorts.length ? [`RTP ports tested: ${testedRtpPorts.length}, all closed=${noRtpPortOpen}.`] : ['No RTP ports were included in the network probe.']),
          ],
          routerOsCommands: [allowRtpCommand],
          confidence: 84,
          confidenceScore: 84,
        },
      ],
      target,
    };
  }

  if (!hasRtpDstNat || !hasSrcNat) {
    return {
      issue: 'Possible NAT issue affecting RTP',
      explanation: 'NAT policy does not fully support RTP media traversal.',
      context: 'Calls may connect but media may be one-way or unstable.',
      cause: !hasRtpDstNat
        ? 'Missing RTP dst-nat rule for UDP 10000-20000.'
        : 'Missing srcnat/masquerade rule for WAN egress.',
      solution: 'Add missing RTP dst-nat/srcnat rules and validate live call media.',
      mikrotikCommands: [
        ...(!hasRtpDstNat ? [addRtpDstNatCommand] : []),
        ...(!hasSrcNat ? [addSrcNatCommand] : []),
      ],
      overallStatus: 'attention_required',
      confidence: 87,
      confidenceScore: 87,
      primaryFinding: {
        rule: 'rtp_nat_incomplete',
        probableCause: 'Possible NAT issue affecting RTP',
        recommendedAction: 'Apply missing NAT rules and retest two-way audio.',
        mikrotikChecks: [`hasRtpDstNat=${hasRtpDstNat}`, `hasSrcNat=${hasSrcNat}`],
        routerOsCommand: !hasRtpDstNat ? addRtpDstNatCommand : addSrcNatCommand,
        routerOsCommands: [
          ...(!hasRtpDstNat ? [addRtpDstNatCommand] : []),
          ...(!hasSrcNat ? [addSrcNatCommand] : []),
        ],
        confidence: 87,
        confidenceScore: 87,
      },
      findings: [
        {
          rule: 'rtp_nat_incomplete',
          probableCause: 'Possible NAT issue affecting RTP',
          recommendedAction: 'Apply missing NAT rules and retest two-way audio.',
          evidence: [
            `MikroTik NAT state: hasRtpDstNat=${hasRtpDstNat}`,
            `MikroTik NAT state: hasSrcNat=${hasSrcNat}`,
          ],
          routerOsCommands: [
            ...(!hasRtpDstNat ? [addRtpDstNatCommand] : []),
            ...(!hasSrcNat ? [addSrcNatCommand] : []),
          ],
          confidence: 87,
          confidenceScore: 87,
        },
      ],
      target,
    };
  }

  return buildNoActionPayload(target);
};

module.exports = {
  buildAnalysis,
};