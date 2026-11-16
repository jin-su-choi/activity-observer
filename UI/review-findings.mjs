import { canonicalLocale, canonicalToken, createI18n } from './i18n.mjs';

// An assessment belongs to one completed review interval. It is accepted only
// when it names the same day, range, head hash and signing key as the report,
// so it is never inferred from counts or carried over to another interval.
// Labels and built-in reasons are stored as canonical tokens and translated
// when they are shown.
const reason = key => canonicalToken('reviewReason', key);
const canonical = createI18n(canonicalLocale);
const label = status => canonical.t('status.' + status);
export function reviewBadge(source, id, findings) {
  const bound = findings?.day === source.day && findings?.after === source.after && findings?.through === source.through &&
    findings?.headHash === source.anchor?.payload?.head_hash && findings?.keyFingerprint === source.anchor?.key_fingerprint;
  const finding = bound && findings.applications && Object.hasOwn(findings.applications, id) && findings.applications[id];
  if (finding && ['normal', 'attention'].includes(finding.status) && typeof finding.reason === 'string' && finding.reason.trim()) {
    return { status: finding.status, label: label(finding.status), reason: finding.reason };
  }
  return { status: 'attention', label: label('attention'), reason: reason('notReviewed') };
}
