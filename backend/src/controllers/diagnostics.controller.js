const { v4: uuidv4 } = require('uuid');
const repository = require('../repositories/diagnostic.repository');
const { runDiagnostics } = require('../services/diagnostics/orchestrator.service');
const HttpError = require('../utils/http-error');

const createDiagnostic = async (req, res, next) => {
  try {
    const { target, ports } = req.body;

    const startedAt = new Date().toISOString();
    const diagnosticOutput = await runDiagnostics({ target, ports });
    const finishedAt = new Date().toISOString();

    const record = {
      id: uuidv4(),
      target,
      ports: ports || [80, 443, 5060],
      status: diagnosticOutput.status,
      startedAt,
      finishedAt,
      results: diagnosticOutput.results,
      checks: diagnosticOutput.checks,
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
