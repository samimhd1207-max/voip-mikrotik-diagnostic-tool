const express = require('express');
const {
  applyMikrotikPortForward,
  applyMikrotikStaticIp,
  applyMikrotikLanNetworkChange,
} = require('../controllers/mikrotik.controller');
const {
  validatePortForwardingRequest,
  validateStaticIpRequest,
  validateLanNetworkChangeRequest,
} = require('../middleware/validate.middleware');

const router = express.Router();

router.post('/port-forward', validatePortForwardingRequest, applyMikrotikPortForward);
router.post('/set-static-ip', validateStaticIpRequest, applyMikrotikStaticIp);
router.post('/change-lan-network', validateLanNetworkChangeRequest, applyMikrotikLanNetworkChange);

module.exports = router;