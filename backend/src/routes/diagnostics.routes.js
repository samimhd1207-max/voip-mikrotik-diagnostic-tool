const express = require('express');
const { createDiagnostic, getDiagnosticById } = require('../controllers/diagnostics.controller');
const { validateCreateDiagnostic } = require('../middleware/validate.middleware');

const router = express.Router();

router.post('/', validateCreateDiagnostic, createDiagnostic);
router.get('/:id', getDiagnosticById);

module.exports = router;
