const { v4: uuidv4 } = require('uuid');
const repository = require('../repositories/diagnostic.repository');
const { runDiagnostics } = require('../services/diagnostics/orchestrator.service');
const { DEFAULT_PORTS } = require('../services/network/port.service');
const HttpError = require('../utils/http-error');

const createDiagnostic = async (req, res, next) => {
  try {
    const { target, ports, expectsSipService, mikrotik } = req.body;

    const startedAt = new Date().toISOString();
    const diagnosticOutput = await runDiagnostics({ target, ports, expectsSipService, mikrotik });
    const finishedAt = new Date().toISOString();
    const mikrotikResult = diagnosticOutput?.results?.mikrotik;

    if (mikrotik && mikrotikResult?.authFailed) {
      throw new HttpError(401, 'MikroTik authentication failed. Please check username/password and retry.', {
        field: 'mikrotik.password',
      });
    }

    if (mikrotik && mikrotikResult?.error && !mikrotikResult?.authFailed) {
      throw new HttpError(400, `MikroTik SSH failed: ${mikrotikResult.error}`, {
        field: 'mikrotik.host',
      });
    }

    const record = {
      id: uuidv4(),
      target,
      ports: ports || DEFAULT_PORTS,
      expectsSipService: Boolean(expectsSipService),
      mikrotikConfigured: Boolean(mikrotik),
      status: diagnosticOutput.status,
      startedAt,
      finishedAt,
      results: diagnosticOutput.results,
      checks: diagnosticOutput.checks,
      analysis: diagnosticOutput.analysis,
    };

    await repository.save(record);

    res.status(201).json({
      id: record.id,
      status: record.status,
      startedAt: record.startedAt,
      finishedAt: record.finishedAt,
    });
  } catch (error) {
    next(error);
  }
};

const getDiagnosticById = async (req, res, next) => {
  try {
    const { id } = req.params;
    const record = await repository.findById(id);

    if (!record) {
      throw new HttpError(404, `Diagnostic ${id} not found`);
    }

    res.status(200).json(record);
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createDiagnostic,
  getDiagnosticById,
};