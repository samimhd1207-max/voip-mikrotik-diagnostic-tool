const isClosed = (portsMap, port) => portsMap.get(port)?.open === false;
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

const buildNoActionPayload = (target) => ({
  issue: 'No issue detected',
  explanation: 'No blocking condition requiring MikroTik change was detected from current probes.',
  context: 'SIP signaling path does not show a definitive firewall/NAT fault from available telemetry.',
  cause: 'No actionable MikroTik fault detected.',
  solution: 'No action required',
  mikrotikCommands: [],
  overallStatus: 'healthy',
  confidence: 35,
  confidenceScore: 35,
  primaryFinding: {
    rule: 'no_action_required',
    probableCause: 'No actionable MikroTik fault detected.',
    recommendedAction: 'No action required',
    mikrotikChecks: ['No blocking firewall/NAT signal found in current dataset.'],
    routerOsCommand: 'N/A',
    routerOsCommands: [],
    confidence: 35,
    confidenceScore: 35,
  },
  findings: [
    {
      rule: 'no_action_required',
      probableCause: 'No actionable MikroTik fault detected.',
      recommendedAction: 'No action required',
      evidence: ['No blocking firewall/NAT signal found in current dataset.'],
      routerOsCommands: [],
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