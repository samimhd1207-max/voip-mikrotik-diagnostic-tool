const express = require('express');
const {
  applyMikrotikPortForward,
  applyMikrotikStaticIp,
  applyMikrotikLanNetworkChange,
  applyMikrotikWifiConfiguration,
  applyMikrotikMailRoute4g,
  runMikrotikAudit,
  applyMikrotikFix,
} = require('../controllers/mikrotik.controller');
const {
  validatePortForwardingRequest,
  validateStaticIpRequest,
  validateLanNetworkChangeRequest,
  validateWifiUpdateRequest,
  validateRouteMail4gRequest,
  validateMikrotikAuditRequest,
  validateMikrotikApplyFixRequest,
} = require('../middleware/validate.middleware');

const router = express.Router();

router.post('/port-forward', validatePortForwardingRequest, applyMikrotikPortForward);
router.post('/set-static-ip', validateStaticIpRequest, applyMikrotikStaticIp);
router.post('/change-lan-network', validateLanNetworkChangeRequest, applyMikrotikLanNetworkChange);
router.post('/update-wifi', validateWifiUpdateRequest, applyMikrotikWifiConfiguration);
router.post('/route-mail-4g', validateRouteMail4gRequest, applyMikrotikMailRoute4g);
router.post('/audit', validateMikrotikAuditRequest, runMikrotikAudit);
router.post('/apply-fix', validateMikrotikApplyFixRequest, applyMikrotikFix);

module.exports = router;