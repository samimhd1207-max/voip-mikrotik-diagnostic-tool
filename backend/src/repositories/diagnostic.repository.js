const fs = require('fs/promises');
const path = require('path');
const env = require('../config/env');
const logger = require('../config/logger');

const inMemoryStore = new Map();
let writeQueue = Promise.resolve();

const ensureStoreFile = async () => {
  const filePath = env.diagnosticsStoreFile;
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
  try {
    await fs.access(filePath);
  } catch {
    await fs.writeFile(filePath, JSON.stringify([]), 'utf8');
  }
};

const loadStore = async () => {
  await ensureStoreFile();
  const raw = await fs.readFile(env.diagnosticsStoreFile, 'utf8');
  const parsed = JSON.parse(raw);
  parsed.forEach((item) => {
    inMemoryStore.set(item.id, item);
  });
};

const flushStore = async () => {
  const payload = JSON.stringify([...inMemoryStore.values()], null, 2);
  writeQueue = writeQueue
    .then(() => fs.writeFile(env.diagnosticsStoreFile, payload, 'utf8'))
    .catch((error) => {
      logger.error({ err: error }, 'Failed to persist diagnostics store');
    });

  await writeQueue;
};

const save = async (record) => {
  inMemoryStore.set(record.id, record);
  await flushStore();
  return record;
};

const findById = async (id) => inMemoryStore.get(id) || null;

module.exports = {
  loadStore,
  save,
  findById,
};
