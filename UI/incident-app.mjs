import { App, applyHostStyleVariables } from '@modelcontextprotocol/ext-apps';
import { applyStaticText, i18n, t, useHostLocale, useReviewZone } from './widget-i18n.mjs';

const app = new App({ name: 'Activity Observer incident', version: '1.0.0' }, { availableDisplayModes: ['inline', 'fullscreen'] });
const status = document.querySelector('#status');
const evidence = document.querySelector('#evidence');
const reasons = document.querySelector('#reasons');
const content = document.querySelector('#incident-content');
const placeholder = document.querySelector('#incident-loading');
const loadingStatus = document.querySelector('#incident-loading-status');
const errorPanel = document.querySelector('#incident-unavailable');
const errorReason = document.querySelector('#incident-unavailable-reason');
let connected = false, rendered = false, loading = false, reference, pending, shown, failure;
const timeout = setTimeout(() => { if (!rendered) fail('incident.missing'); }, 12000);

function fail(key) {
  clearTimeout(timeout);
  failure = key;
  content.hidden = placeholder.hidden = true;
  loadingStatus.textContent = '';
  errorReason.textContent = t(key);
  errorPanel.hidden = false;
}

function add(parent, tag, value) {
  const element = document.createElement(tag);
  element.textContent = value;
  parent.append(element);
  return element;
}

// Incidents store reason codes. Views saved by an earlier server only carry text.
function reasonTexts(view) {
  const codes = Array.isArray(view.reasonCodes) && view.reasonCodes.length === view.reasons.length ? view.reasonCodes : null;
  return view.reasons.map((text, index) => codes && i18n.has('incident.reason.' + codes[index]) ? i18n.reason(codes[index]) : text);
}

function draw(view) {
  useReviewZone(view.timeZone);
  const [title, ...others] = reasonTexts(view);
  const unknown = t('incident.unknown');
  document.querySelector('#title').textContent = title ?? t('incident.fallbackTitle');
  status.textContent = t('incident.status', { time: i18n.dateTime(view.createdAt), id: view.id, revision: view.revision });
  reasons.replaceChildren();
  for (const reason of others) add(reasons, 'li', reason);
  document.querySelector('#verification').textContent = view.coverageGap
    ? t('incident.coverageGap', view.coverageGap)
    : t(view.verified ? 'incident.verified' : 'incident.unverified');
  evidence.replaceChildren();
  for (const row of view.evidence) {
    const card = document.createElement('article');
    add(card, 'h3', row.app + ' · ' + row.kind);
    add(card, 'small', t('incident.record', { time: i18n.dateTime(row.timestamp), id: row.id, pid: row.pid }));
    if (row.path) add(card, 'code', row.path);
    if (row.remote) {
      const sent = row.appAggregate || row.executableAggregate
        ? ' · ' + t('incident.sent', { executable: Boolean(row.executableAggregate), bytes: i18n.integer(Number(row.sent)) }) : '';
      add(card, 'p', (row.protocol || unknown).toUpperCase() + ' ' + row.remote + sent);
    }
    if (row.version) add(card, 'p', t('incident.version', { previous: row.previousVersion || unknown, current: row.version }));
    if (row.team) add(card, 'p', t('incident.team', { previous: row.previousTeam || unknown, current: row.team }));
    for (const path of row.changedPaths ?? []) add(card, 'code', path);
    evidence.append(card);
  }
  document.querySelector('#evidence-toggle').hidden = view.evidence.length === 0;
  document.querySelector('#evidence-summary').textContent = t('incident.evidenceCount', { count: view.evidence.length });
}

function render(view) {
  if (rendered || !view?.id || !Array.isArray(view.reasons) || !Array.isArray(view.evidence) ||
      (reference && (view.id !== reference.incidentId || (reference.revision && view.revision !== reference.revision)))) return;
  rendered = true;
  shown = view;
  clearTimeout(timeout);
  draw(view);
  errorPanel.hidden = placeholder.hidden = true;
  loadingStatus.textContent = '';
  content.hidden = false;
}

function open() {
  if (!connected || rendered) return;
  if (pending) render(pending);
  if (!rendered && reference && !loading) {
    loading = true;
    setTimeout(async () => {
      if (rendered) return;
      try {
        const result = await app.callServerTool({ name: 'read_activity_incident_view', arguments: reference }, { timeout: 8000 });
        if (result.isError) throw Error('Incident unavailable');
        render(result.structuredContent);
      } catch { if (!rendered) fail('incident.missing'); }
    }, 250);
  }
}

function showLanguage() {
  applyStaticText(document.body);
  document.title = t('incident.documentTitle');
  if (rendered || failure) loadingStatus.textContent = '';
  if (shown) draw(shown);
  if (failure) errorReason.textContent = t(failure);
}

app.ontoolinput = ({ arguments: args }) => {
  if (typeof args?.incidentId === 'string' && /^[a-f0-9]{24}$/.test(args.incidentId)) {
    reference = { incidentId: args.incidentId, ...(Number.isSafeInteger(args.revision) && { revision: args.revision }) };
  }
  open();
};
app.ontoolresult = result => {
  if (result.isError && !reference && !rendered) fail('incident.missing');
  pending = result.structuredContent;
  open();
};
function applyHostContext(context) {
  if (typeof context?.locale === 'string' && useHostLocale(context.locale)) showLanguage();
  if (context?.styles?.variables) applyHostStyleVariables(context.styles.variables);
  if (['light', 'dark'].includes(context?.theme)) document.documentElement.style.colorScheme = context.theme;
}
showLanguage();
app.onhostcontextchanged = applyHostContext;
app.onteardown = async () => ({});
app.connect(undefined, { timeout: 8000 }).then(() => {
  connected = true;
  applyHostContext(app.getHostContext());
  open();
}).catch(() => { fail('widget.connectFailed'); });
