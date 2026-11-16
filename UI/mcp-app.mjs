import { App, applyHostStyleVariables } from '@modelcontextprotocol/ext-apps';
import { createIcons, Archive, AppWindow, Asterisk, AudioLines, Braces, CalendarDays, ChartNoAxesColumn, Check, ChevronRight, CircleAlert, CircleCheck, CircleHelp,
  Component, FileQuestion, FlaskConical, FolderSync, GitBranch, GitPullRequest, Globe, Hexagon, Inbox, KeyRound,
  Monitor, MonitorUp, Notebook, OctagonAlert, Package, PanelsTopLeft, Plus, ScanSearch, Shield, ShieldAlert, ShieldCheck, SquareTerminal, Terminal } from 'lucide';
import { installTooltips } from './tooltips.mjs';
import { mountChart } from './chart-view.mjs';
import { installDateRangePicker, positionPopover } from './date-range-picker.mjs';
import { createActivityAttachments } from './activity-attachments.mjs';
import { localizeCardSummary, localizeView, prunedErrors, reviewReferencePattern } from './i18n.mjs';
import { applyStaticText, i18n, t, toolFailure, useHostLocale, useReviewZone } from './widget-i18n.mjs';
import { orderPrograms } from './program-order.mjs';

const root = document.getElementById('security-activity');
const icons = { Archive, AppWindow, Asterisk, AudioLines, Braces, CalendarDays, ChartNoAxesColumn, Check, ChevronRight, CircleAlert, CircleCheck, CircleHelp, Component,
  FileQuestion, FlaskConical, FolderSync, GitBranch, GitPullRequest, Globe, Hexagon, Inbox, KeyRound, Monitor,
  MonitorUp, Notebook, OctagonAlert, Package, PanelsTopLeft, Plus, ScanSearch, Shield, ShieldAlert, ShieldCheck, SquareTerminal, Terminal };
const drawIcons = () => createIcons({ icons, attrs: { width: 16, height: 16 } });
const app = new App({ name: 'Activity Observer', version: '0.1.0' },
  { availableDisplayModes: ['inline', 'fullscreen'] }, { autoResize: true });
const cards = root.querySelector('#oi-review-cards');
const summaryNotice = root.querySelector('#oi-summary-notice');
const dashboard = document.documentElement.dataset.activityObserverMode === 'dashboard';
const periodControls = root.querySelector('#oi-period');
const periodStatus = root.querySelector('#oi-period-status');
const loadingStatus = root.querySelector('#oi-loading-status');
const mainStatePanel = root.querySelector('#oi-main-state');
const cardStatePanel = root.querySelector('#oi-card-state');
const loadError = () => t('widget.reportNotReceived');
let initialized = false, review, pendingData, reviewCards, cardRequest, detailsRequest, mountedProgram, requestedProgram;
let periodRequest, failedDetail, mounted, period;
const attachments = createActivityAttachments(app, () => root.__observer?.updateAttachments?.());

function changeState(surface, state, info) {
  const panel = surface === 'card' ? cardStatePanel : mainStatePanel;
  const retry = panel.querySelector('.oi-state-retry');
  const moveFocus = retry === document.activeElement;
  root.dataset[surface + 'State'] = state;
  updateLoadingStatus();
  if (state !== 'unavailable') {
    retry.onclick = null;
    if (moveFocus) (surface === 'card' ? root.querySelector('#oi-summary-title') : root.querySelector('.oi-main')).focus({ preventScroll: true });
    return;
  }
  const glyph = document.createElement('i');
  glyph.setAttribute('data-lucide', info.icon ?? 'circle-alert');
  panel.querySelector('.oi-state-icon').replaceChildren(glyph);
  panel.querySelector('.oi-state-title').textContent = info.title;
  panel.querySelector('.oi-state-copy p').textContent = info.message;
  retry.hidden = !info.retry;
  retry.onclick = info.retry ?? null;
  drawIcons();
}

function updateLoadingStatus() {
  const surface = root.dataset.compact === 'true' ? 'card' : 'main';
  loadingStatus.textContent = root.dataset[surface + 'State'] === 'loading' ? t('loading.records') : '';
}

function unavailable(surface, title, message, retry, icon) {
  if (surface === 'main' && root.dataset.listState === 'loading') root.dataset.listState = 'empty';
  changeState(surface, 'unavailable', { title, message, retry, icon });
}

function showReviewError(message) {
  unavailable('card', t('state.report.title'), message, review ? retryCards : undefined);
  unavailable('main', t('state.report.title'), message, review ? () => loadDetails(requestedProgram) : undefined);
}

const loadTimeout = dashboard ? null : setTimeout(() => {
  if (!reviewCards && !pendingData && !detailsRequest && !cardRequest) showReviewError(loadError());
}, 10000);
applyStaticText(root);
updateLoadingStatus();
installTooltips(root);
drawIcons();

function reviewReference(throughId, expectedHeadHash, expectedPublicationHash) {
  if (Number.isSafeInteger(throughId) && throughId > 0 &&
      typeof expectedHeadHash === 'string' && /^[a-f0-9]{64}$/.test(expectedHeadHash)) {
    return { throughId, expectedHeadHash,
      ...(typeof expectedPublicationHash === 'string' && /^[a-f0-9]{64}$/.test(expectedPublicationHash) && { expectedPublicationHash }) };
  }
}

function matchesReview(view, expected) {
  const source = view?.source;
  const ref = reviewReference(source?.through, source?.anchor?.payload?.head_hash);
  return view?.schema === 3 && Array.isArray(view.apps) && view.apps.length > 0 && ref &&
    source.through === source.anchor.payload.head_id &&
    (!expected || (ref.throughId === expected.throughId && ref.expectedHeadHash === expected.expectedHeadHash &&
      (!expected.expectedPublicationHash || view.publicationHash === expected.expectedPublicationHash)));
}

async function readReview(ref, programId, signal) {
  const decoder = new TextDecoder();
  const chunks = [];
  let offset = 0;
  for (;;) {
    const result = await app.callServerTool({
      name: 'read_activity_review_view', arguments: { ...ref, offset, ...(programId !== undefined && { programId }) }
    }, { timeout: offset === 0 ? 90000 : 12000, signal });
    const page = result.structuredContent;
    if (result.isError || typeof page?.chunk !== 'string' || !page.chunk) throw toolFailure(result, 'widget.reportNotReceived');
    const bytes = Uint8Array.from(atob(page.chunk), char => char.charCodeAt(0));
    chunks.push(decoder.decode(bytes, { stream: page.nextOffset !== null }));
    if (page.nextOffset === null) break;
    if (page.nextOffset !== offset + bytes.length) throw Error('Invalid review data offset');
    offset = page.nextOffset;
  }
  const view = JSON.parse(chunks.join(''));
  if (!matchesReview(view, ref) || (programId !== undefined && (view.apps.length !== 1 || view.apps[0].id !== programId))) {
    throw Error(t('widget.detailMismatch'));
  }
  return view;
}

async function readPeriod(start, end, signal, referenceId, programId) {
  const decoder = new TextDecoder(), chunks = [];
  let offset = 0, periodId = referenceId;
  for (;;) {
    const result = await app.callServerTool({ name: 'read_activity_period_view', arguments: { start, end, offset, ...(periodId && { periodId }), ...(programId!==undefined && {programId}) } },
      { timeout: 150000, signal });
    const page = result.structuredContent;
    if (result.isError || !page?.periodId || !page.chunk || (periodId && page.periodId !== periodId)) throw toolFailure(result, 'widget.periodFailed');
    periodId = page.periodId;
    const bytes = Uint8Array.from(atob(page.chunk), char => char.charCodeAt(0));
    chunks.push(decoder.decode(bytes, { stream: page.nextOffset !== null }));
    if (page.nextOffset === null) break;
    if (page.nextOffset !== offset + bytes.length) throw Error(t('widget.periodIncomplete'));
    offset = page.nextOffset;
  }
  const data = JSON.parse(chunks.join(''));
  if (data.schema !== 3 || data.source?.start !== start || data.source?.end !== end || !Array.isArray(data.apps)) {
    throw Error(t('widget.periodMismatch'));
  }
  return { data, periodId };
}

function mount(data, periodId) {
  const caps = app.getHostCapabilities() || {};
  const selection = root.__observer?.getState();
  root.__observer?.destroy?.();
  // Labels that name the time zone follow the zone of the view being shown.
  if (useReviewZone(data.source?.timeZone)) { applyStaticText(root); period?.refresh(); }
  try {
    window.mountActivityObserver(localizeView(data, i18n), {
      i18n, drawIcons, selection, dashboard, canReveal: Boolean(caps.serverTools), canMessage: Boolean(caps.message),
      selectProgram: id => { if(dashboard) void loadPeriodProgram(id); else { requestedProgram = id; showReview(); } },
      ...((caps.updateModelContext || caps.experimental?.['openai/message'] && caps.message) && {
        pickActivity: attachments.toggle, isAttached: attachments.has, annotationComment: attachments.comment, positionPopover,
        selectionAction: t(caps.updateModelContext ? 'action.addToChat' : 'action.openDraft')
      }),
      async reveal(args) {
        const result = await app.callServerTool({ name: 'reveal_in_finder', arguments: { ...args,
          ...(periodId && { periodId }), ...(!dashboard && {
            expectedHeadHash: data.source.anchor.payload.head_hash,
            ...(data.publicationHash && { expectedPublicationHash: data.publicationHash })
          }) } });
        if (result.isError || !result.structuredContent?.opened) throw Error('Finder reveal failed');
        return result.structuredContent;
      },
      updateSelection(selection) {
        if (caps.updateModelContext) app.updateModelContext({ structuredContent: selection }).catch(() => {});
      },
      async investigate(text) {
        const result = await app.sendMessage({ role: 'user', content: [{ type: 'text', text }] });
        if (result.isError) throw Error('The host rejected the investigation request');
      }
    });
  } catch {
    mounted = undefined;
    throw Error(t('widget.renderFailed'));
  }
  mounted = { data, periodId };
  clearTimeout(loadTimeout);
  changeState('main', 'ready');
  try { root.__observer.connectChartFactory(mountChart); }
  catch { root.__observer.chartFailure(); }
}

const cardIcons = new Set(['app-window', 'square-terminal', 'git-branch', 'globe', 'asterisk', 'braces', 'monitor-up',
  'folder-sync', 'terminal', 'audio-lines', 'hexagon', 'notebook', 'git-pull-request', 'monitor', 'panels-top-left',
  'key-round', 'component', 'shield-check', 'package', 'flask-conical', 'shield', 'file-question']);
const el = (tag, className, value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
};
const icon = name => {
  const node = el('i');
  node.setAttribute('data-lucide', cardIcons.has(name) ? name : 'app-window');
  node.setAttribute('aria-hidden', 'true');
  return node;
};
function formatMetric(metric) {
  if (metric.detail) return metric.detail;
  if (metric.format !== 'bytes') return `${i18n.integer(metric.value)}${metric.unit || ''}`;
  const bytes = metric.value;
  const [factor, unit] = bytes >= 1e9 ? [1e9, 'GB'] : bytes >= 1e6 ? [1e6, 'MB'] : bytes >= 1e3 ? [1e3, 'KB'] : [1, 'B'];
  return `${i18n.decimal(bytes / factor)} ${unit}`;
}

const cardNav = root.querySelector('#oi-card-nav');
const prev = root.querySelector('#oi-cards-prev'), next = root.querySelector('#oi-cards-next');
function positionCards() {
  const max = cards.scrollWidth - cards.clientWidth;
  cardNav.hidden = max < 3;
  prev.disabled = cards.scrollLeft < 2;
  next.disabled = cards.scrollLeft >= max - 2;
}
let cardIconRequest;

async function loadCardIcons(ref, marks) {
  cardIconRequest?.abort();
  const request = new AbortController();
  cardIconRequest = request;
  if (!app.getHostCapabilities()?.serverTools || !marks.size) return;
  const programIds = [...marks.keys()];
  try {
    // Keep images out of the persisted tool result and each reply small.
    for (let offset = 0; offset < programIds.length; offset += 2) {
      const result = await app.callServerTool({ name: 'read_activity_review_icons', arguments: { ...ref, programIds: programIds.slice(offset, offset + 2) } },
        { signal: request.signal, timeout: 8000 });
      if (request.signal.aborted || result.isError) return;
      for (const [id, src] of Object.entries(result.structuredContent?.icons ?? {})) {
        const mark = marks.get(id);
        if (!mark || typeof src !== 'string' || !/^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(src)) continue;
        const image = el('img');
        image.alt = '';
        image.addEventListener('load', () => { if (!request.signal.aborted) mark.replaceChildren(image); }, { once: true });
        image.src = src;
      }
    }
  } catch { /* An unavailable icon keeps its program glyph. */ }
}
cards.addEventListener('scroll', positionCards, { passive: true });
new ResizeObserver(positionCards).observe(cards);
for (const [button, direction] of [[prev, -1], [next, 1]]) {
  button.addEventListener('click', () => {
    const width = cards.firstElementChild?.getBoundingClientRect().width ?? 0;
    cards.scrollBy({ left: direction * (width + 9), behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' });
  });
}

function displayCards(data) {
  const ref = reviewReference(data?.through, data?.headHash, data?.publicationHash);
  if (!ref || !/^\d{4}-\d{2}-\d{2}$/.test(data.day) || !data.applications?.length ||
      (review && (review.throughId !== ref.throughId || review.expectedHeadHash !== ref.expectedHeadHash ||
        (review.expectedPublicationHash && review.expectedPublicationHash !== ref.expectedPublicationHash)))) return;
  review = ref;
  review ??= ref;
  reviewCards = data;
  clearTimeout(loadTimeout);
  const date = root.querySelector('#oi-card-date');
  date.dateTime = data.day;
  date.textContent = i18n.day(data.day);
  const marks = new Map();
  cards.replaceChildren(...localizeCardSummary(data, i18n).applications.map(program => {
    const item = el('li', 'oi-card');
    const heading = el('div', 'oi-card-head');
    const mark = el('span', 'oi-card-icon');
    mark.append(icon(program.icon));
    marks.set(program.id, mark);
    heading.append(mark, el('h3', '', program.name));
    if (['normal', 'attention', 'threat'].includes(program.status)) {
      const state = el('span', 'oi-card-state', t('status.' + program.status));
      state.dataset.status = program.status;
      heading.append(state);
    }
    const facts = el('dl', 'oi-card-metrics');
    const metrics = (program.metrics ?? []).filter(metric => metric.value > 0).slice(0, 2);
    for (const [label, value] of [[t('card.records'), t('card.recordCount', { count: program.records })], ...metrics.map(metric => [metric.label, formatMetric(metric)])]) {
      const row = el('div');
      row.append(el('dt', '', label), el('dd', '', value));
      facts.append(row);
    }
    const open = el('button', 'oi-card-open', t('card.details'));
    open.type = 'button';
    open.setAttribute('aria-label', t('card.detailsFor', { name: program.name }));
    open.addEventListener('click', () => openProgram(program.id));
    item.append(heading, facts, open);
    return item;
  }));
  cards.hidden = false;
  const verdict = data.verdict ?? data.report?.verdict;
  window.showActivityObserverVerdict(root.querySelector('#oi-card-verdict'), verdict, verdict && t('verdict.' + verdict));
  changeState('card', 'ready');
  drawIcons();
  positionCards();
  void loadCardIcons(ref, marks);
}

async function openProgram(programId) {
  requestedProgram = programId;
  failedDetail = undefined;
  summaryNotice.textContent = '';
  try {
    const result = await app.requestDisplayMode({ mode: 'fullscreen' });
    if (result.mode !== 'fullscreen') throw Error('Fullscreen was not granted');
    applyHostContext({ displayMode: result.mode });
  } catch {
    summaryNotice.textContent = t('widget.fullscreenFailed');
  }
}

async function loadDetails(programId) {
  const retry = () => loadDetails(programId);
  detailsRequest?.controller.abort();
  const controller = new AbortController();
  detailsRequest = { programId, controller };
  changeState('main', 'loading');
  try {
    const data = await readReview(review, programId, controller.signal);
    if (controller.signal.aborted) return;
    mount(data);
    mountedProgram = programId ?? null;
    failedDetail = undefined;
  } catch (error) {
    if (!controller.signal.aborted) {
      failedDetail = programId ?? null;
      const expired = prunedErrors.has(error.code);
      unavailable('main', t(expired ? 'state.detailExpired.title' : 'state.detail.title'), error.message,
        expired ? undefined : retry, expired ? 'archive' : 'circle-alert');
    }
  } finally {
    if (detailsRequest?.controller === controller) detailsRequest = null;
  }
}

function retryCards() {
  cardRequest = undefined;
  changeState('card', 'loading');
  showReview();
}

function showReview() {
  if (!initialized || dashboard) return;
  if (root.dataset.compact === 'true') {
    if (!reviewCards && review && !cardRequest) {
      cardRequest = app.callServerTool({ name: 'read_activity_review_cards', arguments: review }, { timeout: 10000 })
        .then(result => {
          if (result.isError || !result.structuredContent?.applications?.length) throw toolFailure(result, 'widget.reportNotReceived');
          if (!reviewCards) displayCards(result.structuredContent);
        })
        .catch(error => {
          if (!reviewCards) unavailable('card', t('state.report.title'), error.message, retryCards);
        });
    }
    return;
  }
  const programId = requestedProgram ?? reviewCards?.applications[0]?.id;
  if (detailsRequest && detailsRequest.programId !== programId) {
    detailsRequest.controller.abort();
    detailsRequest = null;
    if (mountedProgram === (programId ?? null)) changeState('main', 'ready');
  }
  if (!detailsRequest && mountedProgram === (programId ?? null) && root.__observer) {
    changeState('main', 'ready');
    return;
  }
  if (matchesReview(pendingData, review) && !reviewCards) {
    if (mountedProgram === undefined && failedDetail === undefined) {
      try { mount(pendingData); mountedProgram = null; }
      catch (error) { showReviewError(error.message); }
    }
  } else if (review && (programId !== undefined || !reviewCards) && mountedProgram !== (programId ?? null) &&
      failedDetail !== (programId ?? null) && (!detailsRequest || detailsRequest.programId !== programId)) {
    void loadDetails(programId);
  }
}

function savedToolResult(result) {
  if (reviewReference(result.structuredContent?.through, result.structuredContent?.headHash)) return result;
  for (const item of result.content ?? []) {
    if (item.type !== 'text') continue;
    try {
      const stored = JSON.parse(item.text);
      if (stored?.structuredContent) return stored;
    } catch { /* Some versions keep the summary before clipping the rest of the response. */ }
    const start = /"structuredContent"\s*:\s*/.exec(item.text);
    const end = /,\s*"_meta"\s*:/.exec(item.text);
    if (start && end && end.index > start.index) {
      try { return { structuredContent: JSON.parse(item.text.slice(start.index + start[0].length, end.index)) }; }
      catch { /* Fall back to the original tool arguments. */ }
    }
  }
  return result;
}

app.ontoolinput = ({ arguments: args }) => {
  review ??= reviewReference(args?.throughId, args?.expectedHeadHash, args?.expectedPublicationHash);
  showReview();
};
app.ontoolresult = raw => {
  if (dashboard) return;
  const result = savedToolResult(raw);
  const data = result.structuredContent;
  const referenceText = (result.content ?? []).filter(item => item.type === 'text').map(item => item.text).join('\n');
  const saved = reviewReferencePattern.exec(referenceText);
  const ref = reviewReference(data?.through, data?.headHash, data?.publicationHash) ??
    (saved && reviewReference(Number(saved[1]), saved[2], saved[3]));
  if (ref && (!review || (review.throughId === ref.throughId && review.expectedHeadHash === ref.expectedHeadHash &&
      !review.expectedPublicationHash))) {
    review = ref;
  }
  pendingData = result._meta?.activityReview;
  if (reviewReference(data?.through, data?.headHash) && Array.isArray(data.applications)) {
    const applications = data.applicationCount !== undefined ? data.applications
      : orderPrograms(data.applications ?? []).slice(0, 6).map(a => ({ ...a, status: a.review?.status }));
    displayCards({ ...data, applications });
  }
  if (result.isError && !reviewCards && !review) showReviewError(loadError());
  showReview();
};
// A language change redraws what is on screen from the same data.
function changeLanguage() {
  applyStaticText(root);
  period?.refresh();
  showPeriodNotices();
  if (reviewCards) displayCards(reviewCards);
  if (mounted && root.__observer) {
    const state = root.dataset.mainState;
    try { mount(mounted.data, mounted.periodId); } catch { /* The earlier view stays in place. */ }
    if (state !== 'ready') root.dataset.mainState = state;
  }
  updateLoadingStatus();
}

function applyHostContext(context) {
  if (typeof context.locale === 'string' && useHostLocale(context.locale)) changeLanguage();
  if (context.styles?.variables) applyHostStyleVariables(context.styles.variables);
  attachments?.receive(context);
  window.applyActivityObserverHostContext(context);
  root.__observer?.refreshTheme?.();
  updateLoadingStatus();
  const maxHeight = context.containerDimensions?.maxHeight;
  if (root.dataset.displayMode === 'fullscreen' && Number.isFinite(maxHeight) && maxHeight > window.innerHeight) {
    // A host may resize the iframe only after it receives a height notification.
    app.sendSizeChanged({ height: Math.floor(maxHeight) }).catch(() => {});
  }
  showReview();
}

document.addEventListener('fullscreenchange', showReview);
app.onhostcontextchanged = applyHostContext;
app.onteardown = async () => {
  periodRequest?.abort();
  detailsRequest?.controller.abort();
  cardIconRequest?.abort();
  root.__observer?.destroy?.();
  return {};
};
let selectedPeriod, periodNotices = [];
const showPeriodNotices = () => { periodStatus.textContent = periodNotices.map(key => t(key)).join(' '); };
async function loadPeriodProgram(programId) {
  if(!selectedPeriod)return;
  periodRequest?.abort();
  const request=new AbortController();periodRequest=request;
  const ref=selectedPeriod;
  changeState('main','loading');
  try {
    const {data}=await readPeriod(ref.start,ref.end,request.signal,ref.id,programId);
    if(request.signal.aborted || selectedPeriod!==ref)return;
    if(data.apps.length!==1 || data.apps[0].id!==programId)throw Error(t('widget.programMismatch'));
    mount(data,ref.id);
  } catch(error) { if(!request.signal.aborted)unavailable('main',t('state.program.title'),error.message,()=>loadPeriod({start:ref.start,end:ref.end})); }
}
async function loadPeriod({ start, end }) {
  selectedPeriod=undefined;
  periodRequest?.abort();
  const request = new AbortController();
  periodRequest = request;
  const annotationPanel = root.querySelector('#oi-selection');
  if (annotationPanel.matches(':popover-open')) annotationPanel.hidePopover();
  root.dataset.listState = 'loading';
  root.querySelector('#oi-app-total').textContent = '';
  changeState('main', 'loading');
  periodNotices = [];
  showPeriodNotices();
  try {
    const { data, periodId } = await readPeriod(start, end, request.signal);
    if (request.signal.aborted) return;
    const retained = data.source.pruned > 0 && data.source.firstDay && start <= data.source.firstDay;
    const catalog=data.catalog ?? data.apps;
    if (!catalog.length) {
      root.dataset.listState = 'empty';
      root.querySelector('#oi-app-total').textContent = '';
      unavailable('main', t(retained ? 'state.noRetained.title' : 'state.empty.title'),
        t(retained ? 'state.noRetained.body' : 'state.empty.body'), undefined, retained ? 'archive' : 'inbox');
      return;
    }
    const previous=root.__observer?.getState()?.selected;
    selectedPeriod={start,end,id:periodId};
    mount(data,periodId);
    changeState('main','loading');
    await loadPeriodProgram(catalog.some(app=>app.id===previous)?previous:orderPrograms(catalog)[0].id);
    if(selectedPeriod?.id!==periodId)return;
    periodNotices = [retained && 'notice.pruned', !data.source.collecting && 'notice.collector'].filter(Boolean);
    showPeriodNotices();
  } catch (error) {
    if (!request.signal.aborted) {
      root.dataset.listState = 'empty';
      root.querySelector('#oi-app-total').textContent = '';
      unavailable('main', t('state.period.title'), error.message, () => loadPeriod({ start, end }));
    }
  }
}

app.connect(undefined, { timeout: 8000 }).then(() => {
  applyHostContext(app.getHostContext() || {});
  initialized = true;
  if (dashboard) {
    periodControls.hidden = false;
    period = installDateRangePicker(root, loadPeriod);
  } else showReview();
}).catch(() => {
  clearTimeout(loadTimeout);
  root.dataset.listState = 'empty';
  showReviewError(t('widget.connectFailed'));
});
