import { canonicalLocale, canonicalToken, createI18n } from './i18n.mjs';

// An assessment belongs to one completed review interval. It is accepted only
// when it names the same day, range, head hash and signing key as the report,
// so it is never inferred from counts or carried over to another interval.
// Labels and built-in reasons are stored as canonical tokens and translated
// when they are shown.
const reason = key => canonicalToken('reviewReason', key);
const canonical = createI18n(canonicalLocale);
const badge = (status, text) => ({ status, label: canonical.t('status.' + status), reason: text });
const statuses = ['normal', 'attention', 'threat'];
// What the reviewer may state once for every program that raised no lead. A
// threat is always named program by program.
const sharedStatuses = ['normal', 'attention'];
const stated = (finding, allowed) => Boolean(finding) && allowed.includes(finding.status) && typeof finding.reason === 'string' && finding.reason.trim() !== '';
const bound = (source, findings) =>
  findings?.day === source.day && findings?.after === source.after && findings?.through === source.through &&
  findings?.headHash === source.anchor?.payload?.head_hash && findings?.keyFingerprint === source.anchor?.key_fingerprint;

export function reviewBadge(source, id, findings) {
  if (bound(source, findings)) {
    const finding = findings.applications && Object.hasOwn(findings.applications, id) && findings.applications[id];
    if (stated(finding, statuses)) return badge(finding.status, finding.reason);
    if (stated(findings.others, sharedStatuses)) return badge(findings.others.status, findings.others.reason);
  }
  return badge('attention', reason('notReviewed'));
}

// A published review cannot be corrected, so it is stored only when its
// findings are complete and its verdict agrees with them. Returns what stands
// in the way, or nothing. programs carry the badges made from these findings.
export function reviewProblem(verdict, source, findings, programs) {
  const listed = ids => ids.slice(0, 5).map(id => JSON.stringify(id)).join(', ') + (ids.length > 5 ? ' and ' + (ids.length - 5) + ' more' : '');
  if (!bound(source, findings)) return 'findings must name this interval: day, after, through, headHash and keyFingerprint';
  const applications = findings.applications ?? {};
  if (typeof applications !== 'object' || Array.isArray(applications)) return 'findings.applications must be an object keyed by program ID';
  const known = new Set(programs.map(program => program.id));
  const unknown = Object.keys(applications).filter(id => !known.has(id));
  if (unknown.length) {
    return 'findings.applications names programs without records on ' + source.day + ': ' + listed(unknown) +
      '. Use the id of each entry in observed.programs, and describe a program from another day in report.activity';
  }
  const incomplete = Object.keys(applications).filter(id => !stated(applications[id], statuses));
  if (incomplete.length) return 'Each finding needs a status (' + statuses.join(', ') + ') and a reason: ' + listed(incomplete);
  if (findings.others !== undefined && !stated(findings.others, sharedStatuses)) return 'findings.others needs a status (' + sharedStatuses.join(' or ') + ') and a reason';
  const marked = status => programs.filter(program => program.review?.status === status).map(program => program.id);
  const threats = marked('threat'), open = marked('attention');
  if (threats.length && verdict !== 'threat') return 'The verdict is ' + verdict + ', but these programs are marked threat: ' + listed(threats);
  if (verdict === 'clear' && open.length) {
    return 'The verdict is clear, but ' + (open.length === 1 ? 'a program is' : open.length + ' programs are') + ' not marked normal: ' + listed(open) +
      '. Give each lead a finding, and state findings.others for the programs that raised none';
  }
}
