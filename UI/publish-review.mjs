import { readFileSync } from 'node:fs';
import { collectReviewSnapshot, prepareViewData } from './build-widget.mjs';
import { installedReviewDir, reviewReportSchema } from './published-review.mjs';
import { readReviewPublication, reviewPublication, reviewPublicationHash, saveReviewPublication } from './review-history.mjs';

try {
  // All inputs are data from the completed review, not commands or a local
  // checkpoint. The exporter verifies the exact interval before publishing it.
  const { anchor, after, previousHash, day, findings, report } = JSON.parse(readFileSync(0, 'utf8'));
  const narrative = report === undefined ? undefined : reviewReportSchema.parse(report);
  const head = anchor?.payload;
  let publication = head && readReviewPublication(installedReviewDir, head.head_id, head.head_hash);
  if (publication) {
    if (publication.source.after !== after || publication.source.day !== day || publication.previousHash !== previousHash) {
      throw Error('The requested interval differs from the published review');
    }
  } else {
    const data = collectReviewSnapshot({ anchor, after, previousHash, day, reviewedOnly: true });
    const view = prepareViewData(data, findings);
    if (narrative) view.report = narrative;
    publication = saveReviewPublication(installedReviewDir, reviewPublication(view, previousHash), view.apps);
  }
  const { through, rowsRead, reviewedRows, outsideDayRows, dayRows } = publication.source;
  console.log(JSON.stringify({ day, after, through, headHash: head.head_hash, publicationHash: reviewPublicationHash(publication), rowsRead, reviewedRows, outsideDayRows, dayRows,
    applications: publication.applications.map(({ id, name, records, review }) => ({ id, name, records, review })) }));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
