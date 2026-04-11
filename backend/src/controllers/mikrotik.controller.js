const {
  applyPortForwarding,
  applyStaticPublicIp,
  applyLanNetworkChange,
  applyWifiConfiguration,
  applyMailRoutingVia4g,
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

module.exports = {
  applyMikrotikPortForward,
  applyMikrotikStaticIp,
  applyMikrotikLanNetworkChange,
  applyMikrotikWifiConfiguration,
  applyMikrotikMailRoute4g,
};