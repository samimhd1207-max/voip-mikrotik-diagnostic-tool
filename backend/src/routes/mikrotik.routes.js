const express = require('express');
const {
  applyMikrotikPortForward,
  applyMikrotikStaticIp,
  applyMikrotikLanNetworkChange,
  applyMikrotikWifiConfiguration,
  applyMikrotikMailRoute4g,
} = require('../controllers/mikrotik.controller');
const {
  validatePortForwardingRequest,
  validateStaticIpRequest,
  validateLanNetworkChangeRequest,
  validateWifiUpdateRequest,
  validateRouteMail4gRequest,
} = require('../middleware/validate.middleware');

const router = express.Router();

router.post('/port-forward', validatePortForwardingRequest, applyMikrotikPortForward);
router.post('/set-static-ip', validateStaticIpRequest, applyMikrotikStaticIp);
router.post('/change-lan-network', validateLanNetworkChangeRequest, applyMikrotikLanNetworkChange);
router.post('/update-wifi', validateWifiUpdateRequest, applyMikrotikWifiConfiguration);
router.post('/route-mail-4g', validateRouteMail4gRequest, applyMikrotikMailRoute4g);

module.exports = router;