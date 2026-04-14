const {
  applyPortForwarding,
  applyStaticPublicIp,
  applyLanNetworkChange,
  applyWifiConfiguration,
  applyMailRoutingVia4g,
  runAllAudits,
  parseMikrotikOutput,
  executeMikrotikCommand,
} = require('../services/mikrotik/mikrotik.service');

const applyMikrotikPortForward = async (req, res, next) => {
  try {
    const { mikrotik, config } = req.body;
    const payload = await applyPortForwarding({ mikrotik, config });

    res.status(200).json({
      success: true,
      commands: payload.commands,
      skipped: payload.skipped,
    });
  } catch (error) {
    next(error);
  }
};

const applyMikrotikStaticIp = async (req, res, next) => {
  try {
    const { mikrotik, config } = req.body;
    const payload = await applyStaticPublicIp({ mikrotik, config });

    res.status(200).json({
      success: true,
      commands: payload.commands,
      skipped: payload.skipped,
    });
  } catch (error) {
    next(error);
  }
};

const applyMikrotikLanNetworkChange = async (req, res, next) => {
  try {
    const { mikrotik, config } = req.body;
    const payload = await applyLanNetworkChange({ mikrotik, config });

    res.status(200).json({
      success: true,
      commands: payload.commands,
    });
  } catch (error) {
    next(error);
  }
};

const applyMikrotikWifiConfiguration = async (req, res, next) => {
  try {
    const { mikrotik, config } = req.body;
    const payload = await applyWifiConfiguration({ mikrotik, config });

    res.status(200).json({
      success: true,
      commands: payload.commands,
    });
  } catch (error) {
    next(error);
  }
};

const applyMikrotikMailRoute4g = async (req, res, next) => {
  try {
    const { mikrotik, config } = req.body;
    const payload = await applyMailRoutingVia4g({ mikrotik, config });

    res.status(200).json({
      success: true,
      mode: payload.mode,
      commands: payload.commands,
      skipped: payload.skipped,
    });
  } catch (error) {
    next(error);
  }
};

const applyMikrotikFix = async (req, res, next) => {
  try {
    const { mikrotik, command } = req.body;
    const result = await executeMikrotikCommand(command, mikrotik);

    res.status(200).json({
      success: true,
      result,
    });
  } catch (error) {
    next(error);
  }
};
const runMikrotikAudit = async (req, res, next) => {
  try {
    const { mikrotik } = req.body;
    const issues = await runCoreNetworkAudit(mikrotik);

    res.status(200).json(issues);
  } catch (error) {
    next(error);
  }
};

module.exports = {
  applyMikrotikPortForward,
  applyMikrotikStaticIp,
  applyMikrotikLanNetworkChange,
  applyMikrotikWifiConfiguration,
  applyMikrotikMailRoute4g,
  runMikrotikAudit,
  applyMikrotikFix,
};