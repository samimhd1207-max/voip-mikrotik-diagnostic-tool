const isClosed = (portsMap, port) => portsMap.get(port)?.open === false;
const looksVoipRelatedTarget = (target) => /\b(sip|voip|pbx|asterisk|trunk|softswitch)\b/i.test(target);

const allowSip5060Command =
  '/ip firewall filter add chain=forward action=accept protocol=udp dst-port=5060 comment="Allow SIP 5060"; /ip firewall filter move [find where comment="Allow SIP 5060"] 0';

const addSipDstNatCommand =
  '/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-port=5060 to-addresses=192.168.88.10 to-ports=5060 comment="SIP dst-nat 5060"';
const addRtpDstNatCommand =
  '/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-port=10000-20000 to-addresses=192.168.88.10 to-ports=10000-20000 comment="RTP dst-nat 10000-20000"';
const addSrcNatCommand =
  '/ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment="VoIP src-nat"';
const allowRtpCommand =
  '/ip firewall filter add chain=forward action=accept protocol=udp dst-port=10000-20000 comment="Allow RTP media"; /ip firewall filter move [find where comment="Allow RTP media"] 0';

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

  if (sipPortOpen && (!hasRtpDstNat || !hasSrcNat || noRtpPortOpen)) {
    return {
      issue: 'possible one-way audio due to RTP/NAT issue',
      explanation: 'SIP signaling is reachable but RTP media path is incomplete.',
      context: 'Calls may establish successfully while audio is one-way or absent.',
      cause: !hasRtpDstNat
        ? 'RTP dst-nat missing for UDP media range.'
        : !hasSrcNat
        ? 'srcnat/masquerade missing for outbound media.'
        : 'RTP ports tested are closed from probe source.',
      solution: 'Add RTP dst-nat + srcnat and allow RTP media range in firewall.',
      mikrotikCommands: [addRtpDstNatCommand, addSrcNatCommand, allowRtpCommand],
      overallStatus: 'attention_required',
      confidence: hasRtpDstNat || hasSrcNat ? 74 : 89,
      confidenceScore: hasRtpDstNat || hasSrcNat ? 74 : 89,
      primaryFinding: {
        rule: 'possible_one_way_audio_rtp_nat',
        probableCause: 'possible one-way audio due to RTP/NAT issue',
        recommendedAction: 'Configure RTP NAT/media rules and re-test call audio in both directions.',
        mikrotikChecks: [
          `hasRtpDstNat=${hasRtpDstNat}`,
          `hasSrcNat=${hasSrcNat}`,
          `rtpPortsTested=${testedRtpPorts.length}`,
          `rtpAllClosed=${noRtpPortOpen}`,
        ],
        routerOsCommand: addRtpDstNatCommand,
        routerOsCommands: [addRtpDstNatCommand, addSrcNatCommand, allowRtpCommand],
        confidence: hasRtpDstNat || hasSrcNat ? 74 : 89,
        confidenceScore: hasRtpDstNat || hasSrcNat ? 74 : 89,
      },
      findings: [
        {
          rule: 'possible_one_way_audio_rtp_nat',
          probableCause: 'possible one-way audio due to RTP/NAT issue',
          recommendedAction: 'Configure RTP NAT/media rules and re-test call audio in both directions.',
          evidence: [
            'SIP 5060 is open/reachable.',
            `MikroTik NAT state: hasRtpDstNat=${hasRtpDstNat}, hasSrcNat=${hasSrcNat}.`,
            ...(testedRtpPorts.length ? [`RTP ports tested: ${testedRtpPorts.length}, all closed=${noRtpPortOpen}.`] : ['No RTP ports were included in the network probe.']),
          ],
          routerOsCommands: [addRtpDstNatCommand, addSrcNatCommand, allowRtpCommand],
          confidence: hasRtpDstNat || hasSrcNat ? 74 : 89,
          confidenceScore: hasRtpDstNat || hasSrcNat ? 74 : 89,
        },
      ],
      target,
    };
  }

  if (!hasSrcNat) {
    return {
      issue: 'NAT issue detected',
      explanation: 'SIP/NAT path is missing outbound source NAT policy.',
      context: 'Registrations/calls can fail intermittently due to invalid source addressing.',
      cause: 'Missing srcnat/masquerade rule for WAN egress.',
      solution: 'Add source NAT masquerade on WAN.',
      mikrotikCommands: [addSrcNatCommand],
      overallStatus: 'attention_required',
      confidence: 86,
      confidenceScore: 86,
      primaryFinding: {
        rule: 'srcnat_missing',
        probableCause: 'Missing srcnat/masquerade rule.',
        recommendedAction: 'Add srcnat masquerade and retry registration/calls.',
        mikrotikChecks: ['MikroTik analysis reports hasSrcNat=false.'],
        routerOsCommand: addSrcNatCommand,
        routerOsCommands: [addSrcNatCommand],
        confidence: 86,
        confidenceScore: 86,
      },
      findings: [
        {
          rule: 'srcnat_missing',
          probableCause: 'Missing srcnat/masquerade rule.',
          recommendedAction: 'Add srcnat masquerade and retry registration/calls.',
          evidence: ['MikroTik analysis reports hasSrcNat=false.'],
          routerOsCommands: [addSrcNatCommand],
          confidence: 86,
          confidenceScore: 86,
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