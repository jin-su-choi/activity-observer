import { existsSync, closeSync, openSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { digest, reviewReportSchema } from './published-review.mjs';
import { programMetrics } from './metrics.mjs';
import { canonicalLocale, createI18n } from './i18n.mjs';
import { orderPrograms } from './program-order.mjs';

// Published card values are written with the canonical labels. Widgets and
// the server translate them by metric ID when they are shown.
const canonical = createI18n(canonicalLocale);

export function reviewApplication(app) {
  return {
    id: app.id, name: app.name, records: app.records, icon: app.icon,
    review: app.review,
    metrics: programMetrics(app, 'all', canonical).metrics.map(({ id, label, value, unit, format, note }) => ({ id, label, value, unit, format, note }))
  };
}

export function reviewProgramDigest(app, schema = 1) {
  const { iconData, review, ...detail } = app;
  if (schema === 1) return digest(JSON.stringify(detail));
  const { name, icon, type, activity, ...facts } = detail;
  return digest(JSON.stringify({ ...facts, activity: activity.map(({ label, ...row }) => row) }));
}

// Selection references are reconstructed from the authenticated event rows.
// They are presentation metadata added after the original report was published.
export function reviewDetailWithoutReferences(app) {
  const copy=structuredClone(app);
  delete copy.programKey;
  for(const row of [...copy.activity,...copy.endpoints]) delete row.sample;
  for(const bin of [...copy.hours,...Object.values(copy.days ?? {})]) delete bin.eventBounds;
  return copy;
}

export function reviewPublicationHash(publication) {
  return digest(JSON.stringify(publication));
}

export function reviewCardSummary(source, applications) {
  const cards = orderPrograms(applications).slice(0, 6).map(({ id, name, records, review, icon, metrics }) => ({
    id, name, records, icon, status: review?.status,
    metrics: metrics?.filter(metric => metric.value != null).map(({ id, label, value, unit, format, note }) => ({
      id, label, value, unit, format, ...(note?.type === 'text' && { detail: note.value })
    }))
  }));
  return {
    day: source.day, after: source.after, through: source.through, headHash: source.anchor.payload.head_hash,
    records: source.rowsRead, reviewedRecords: source.reviewedRows ?? source.rowsRead, outsideDayRecords: source.outsideDayRows ?? 0,
    dayRecords: source.dayRows ?? { [source.day]: source.rowsRead }, applicationCount: applications.length, applications: cards
  };
}

export function reviewPublication(view, previousHash) {
  const publication = {
    schema: 2, source: view.source, previousHash, report: view.report,
    applications: view.apps.map(app => ({ ...reviewApplication(app), detailHash: reviewProgramDigest(app, 2) }))
  };
  return { ...publication, cards: reviewCardSummary(publication.source, publication.applications).applications };
}

function validatePublication(publication) {
  const { schema, source, previousHash, applications } = publication;
  if (![1, 2].includes(schema) || !Number.isSafeInteger(source?.after) || !Number.isSafeInteger(source.through) || source.through <= source.after ||
      source.anchor?.payload?.head_id !== source.through || !/^[0-9a-f]{64}$/.test(source.anchor?.payload?.head_hash) ||
      !/^[0-9a-f]{64}$/.test(previousHash) || source.integrity !== 'verified' || !/^\d{4}-\d{2}-\d{2}$/.test(source.day) ||
      !Array.isArray(applications) || !applications.length || new Set(applications.map(app => app.id)).size !== applications.length ||
      applications.some(app => typeof app.id !== 'string' || typeof app.name !== 'string' || !Number.isSafeInteger(app.records)) ||
      applications.reduce((count, app) => count + app.records, 0) !== source.rowsRead) throw Error('Invalid review publication');
  if (publication.report !== undefined) reviewReportSchema.parse(publication.report);
  return publication;
}

const isAppIcon = value => typeof value === 'string' && value.length <= 40022 && /^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(value);

export function saveReviewPublication(bundleDir, publication, appsWithIcons = []) {
  const { source } = validatePublication(publication);
  const path = resolve(bundleDir, 'review-history.sqlite');
  mkdirSync(bundleDir, { recursive: true, mode: 0o700 });
  closeSync(openSync(path, 'a', 0o600));
  const db = new DatabaseSync(path);
  try {
    db.exec(`PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS publications (
        through_id INTEGER PRIMARY KEY, head_hash TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL
      ) WITHOUT ROWID;`);
    const cards = publication.cards ?? reviewCardSummary(source, publication.applications).applications;
    const payload = JSON.stringify({ ...publication, cards });
    db.exec('BEGIN IMMEDIATE');
    // Once a range is published, a retry leaves its review and card values intact.
    db.prepare('INSERT OR IGNORE INTO publications VALUES (?, ?, ?, ?)').run(source.through, source.anchor.payload.head_hash, payload, digest(payload));
    if (appsWithIcons.length) saveReviewIcons(db, publication, appsWithIcons);
    db.exec('COMMIT');
  } finally { db.close(); }
  const saved = readReviewPublication(bundleDir, source.through, source.anchor.payload.head_hash);
  if (!saved || saved.previousHash !== publication.previousHash || saved.source.after !== source.after || saved.source.day !== source.day) {
    throw Error('Review publication conflicts with the saved interval');
  }
  return saved;
}

function saveReviewIcons(db, { source, applications }, apps) {
  const headHash = source.anchor.payload.head_hash;
  if (!db.prepare('SELECT 1 FROM publications WHERE through_id = ? AND head_hash = ?').get(source.through, headHash)) return;
  db.exec(`CREATE TABLE IF NOT EXISTS icon_assets (
      digest TEXT PRIMARY KEY, image TEXT NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS publication_icons (
      through_id INTEGER NOT NULL, program_id TEXT NOT NULL, digest TEXT NOT NULL,
      PRIMARY KEY (through_id, program_id)
    ) WITHOUT ROWID;`);
  const insertImage = db.prepare('INSERT OR IGNORE INTO icon_assets VALUES (?, ?)');
  const insertReference = db.prepare('INSERT OR IGNORE INTO publication_icons VALUES (?, ?, ?)');
  const knownPrograms = new Set(applications.map(app => app.id));
  for (const app of apps) {
    if (!knownPrograms.has(app.id) || !isAppIcon(app.iconData)) continue;
    const imageHash = digest(app.iconData);
    insertImage.run(imageHash, app.iconData);
    insertReference.run(source.through, app.id, imageHash);
  }
}

export function readReviewIcons(bundleDir, throughId) {
  const path = resolve(bundleDir, 'review-history.sqlite');
  if (!existsSync(path)) return new Map();
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    db.exec('PRAGMA busy_timeout=5000');
    if (!db.prepare("SELECT 1 FROM sqlite_schema WHERE name = 'publication_icons'").get()) return new Map();
    const rows = throughId === undefined
      ? db.prepare(`SELECT program_id, image FROM publication_icons JOIN icon_assets USING (digest)
          WHERE (program_id, through_id) IN (SELECT program_id, MAX(through_id) FROM publication_icons GROUP BY program_id)`).all()
      : db.prepare('SELECT program_id, image FROM publication_icons JOIN icon_assets USING (digest) WHERE through_id = ?').all(throughId);
    return new Map(rows.filter(row => isAppIcon(row.image)).map(row => [row.program_id, row.image]));
  } finally { db.close(); }
}

export function readReviewPublication(bundleDir, throughId, headHash) {
  const path = resolve(bundleDir, 'review-history.sqlite');
  if (!existsSync(path)) return null;
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    db.exec('PRAGMA busy_timeout=5000');
    const row = throughId === undefined
      ? db.prepare('SELECT * FROM publications ORDER BY through_id DESC LIMIT 1').get()
      : headHash === undefined
        ? db.prepare('SELECT * FROM publications WHERE through_id = ?').get(throughId)
        : db.prepare('SELECT * FROM publications WHERE through_id = ? AND head_hash = ?').get(throughId, headHash);
    if (!row) return null;
    if (digest(row.payload) !== row.digest) throw Error('Review publication digest mismatch');
    const publication = validatePublication(JSON.parse(row.payload));
    if (publication.source.through !== row.through_id || publication.source.anchor.payload.head_hash !== row.head_hash) throw Error('Review publication identity mismatch');
    return publication;
  } finally { db.close(); }
}
