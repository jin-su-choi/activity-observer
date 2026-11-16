import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile, rename, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { z } from 'zod';

export const digest = text => createHash('sha256').update(text).digest('hex');
export { installedUiDir, installedReviewDir } from './paths.mjs';
// Every review ends with one verdict. Reports published before verdicts
// existed have none.
export const reviewVerdicts = ['clear', 'threat', 'inconclusive'];
export const reviewReportSchema = z.object({
  verdict: z.enum(reviewVerdicts).optional(),
  conclusion: z.string().trim().min(1).max(500),
  activity: z.string().trim().min(1).max(3000),
  collection: z.string().trim().min(1).max(1500),
  integrity: z.string().trim().min(1).max(1500)
}).strict();

function validate(view) {
  const source = view?.source;
  if (view?.schema !== 3 || !view.apps?.length || source?.integrity !== 'verified' ||
      !Number.isSafeInteger(source.through) || source.through !== source.anchor?.payload?.head_id ||
      !/^[0-9a-f]{64}$/.test(source.anchor?.payload?.head_hash || '') ||
      view.apps.reduce((n, a) => n + a.records, 0) !== source.rowsRead) throw Error('Invalid reviewed presentation');
  if (source.reviewedRows !== source.rowsRead + source.outsideDayRows ||
      source.dayRows?.[source.day] !== source.rowsRead ||
      Object.values(source.dayRows || {}).reduce((n, v) => n + v, 0) !== source.reviewedRows) throw Error('Review day totals do not match');
  if (view.report !== undefined) reviewReportSchema.parse(view.report);
  return view;
}

export async function publishReview(view, bundleDir) {
  validate(view);
  const path = resolve(bundleDir, 'published-review.json');
  const temporary = path + '.' + randomBytes(8).toString('hex') + '.tmp';
  try {
    await writeFile(temporary, JSON.stringify({ schema: 1, viewSha256: digest(JSON.stringify(view)), view }), { mode: 0o600, flag: 'wx' });
    await rename(temporary, path);
  } finally {
    await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}

export async function readPublishedReview(bundleDir) {
  let text;
  try { text = await readFile(resolve(bundleDir, 'published-review.json'), 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  const { schema, viewSha256, view } = JSON.parse(text);
  if (schema !== 1 || viewSha256 !== digest(JSON.stringify(view))) throw Error('Published presentation hash mismatch');
  return validate(view);
}
