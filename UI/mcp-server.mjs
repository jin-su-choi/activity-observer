import { McpServer, ResourceTemplate } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { registerAppResource, registerAppTool, RESOURCE_MIME_TYPE } from '@modelcontextprotocol/ext-apps/server';
import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { setImmediate as yieldToServer } from 'node:timers/promises';
import { createFinderRevealer } from './finder.mjs';
import { digest, installedReviewDir, readPublishedReview, reviewReportSchema, reviewVerdicts } from './published-review.mjs';
import { readReviewIcons, readReviewPublication, reviewApplication, reviewCardSummary, reviewProgramDigest, reviewDetailWithoutReferences, reviewPublicationHash } from './review-history.mjs';
import { activityPeriodBounds, activityPeriodRetained, assertPublishedRetained, beginActivityReview, checkMcpIsolation, createActivityPeriodSummary, installedMcpBuild,
  openActivityPeriod, readActivityCatalog, readCatalogProgram, readActivityPage, readActivityPeriodPage, readActivitySelection, readPublishedPrograms } from './build-widget.mjs';
import { incidentIdPattern, listIncidentViews, readIncidentView } from './incident-store.mjs';
import { canonicalLocale, localizeApplication, localizeCardSummary } from './i18n.mjs';
import { errorResult, fail, serverI18n } from './i18n-server.mjs';
import { orderPrograms } from './program-order.mjs';
import { systemZone } from './zone.mjs';
import { guardObserved } from './untrusted.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
const eventId = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const reviewReferenceFields = { throughId: eventId, expectedHeadHash: sha256, expectedPublicationHash: sha256.optional() };
const reviewAnchor = z.object({
  algorithm: z.literal('ECDSA-P256-SHA256'),
  key_fingerprint: sha256,
  payload: z.object({
    schema: z.literal(1), created_at: z.number(), head_id: eventId, head_hash: sha256,
    daily_statistics_hash: sha256, inventory_hash: sha256
  }).strict(),
  signature: z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/).max(128)
}).strict();
const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
const viewChunkBytes = 32 * 1024;
const reviewChunkBytes = 8 * 1024;
const detailedCacheBytes = 12 * 1024 * 1024;
const periodInput = z.object({ start: z.string().date(), end: z.string().date() });
const periodId = z.string().uuid();
const selectionInput = periodInput.extend({
  throughId: eventId, expectedHeadHash: sha256, programKey: sha256,
  reviewAfter: eventId.optional(), expectedPublicationHash: sha256.optional(),
  category: z.enum(['all', 'files', 'launch', 'inputs', 'network', 'other']),
  startHour: z.number().int().min(0).max(23).optional(), endHour: z.number().int().min(0).max(23).optional(),
  firstEventId: eventId.optional(), lastEventId: eventId.optional(),
  eventId: eventId.optional(), eventHash: sha256.optional(), after: eventId.optional()
}).strict();
export async function loadBundle(bundleDir = resolve(dir, 'dist'), historyDir = bundleDir) {
  const manifest = JSON.parse(await readFile(resolve(bundleDir, 'manifest.json'), 'utf8'));
  const html = await readFile(resolve(bundleDir, 'activity-review.html'), 'utf8');
  if (digest(html) !== manifest.htmlSha256) throw Error('Presentation HTML changed; rebuild the MCP App');
  const readView = async (throughId, headHash) => {
    const matches = view => (throughId === undefined || view?.source.through === throughId) &&
      (headHash === undefined || view?.source.anchor.payload.head_hash === headHash);
    const published = await readPublishedReview(historyDir);
    if (published && matches(published)) return published;
    if (!manifest.viewSha256) return null;
    const raw = await readFile(resolve(bundleDir, 'review.view.json'), 'utf8');
    if (digest(raw) !== manifest.viewSha256) throw Error('Initial presentation bundle changed');
    const view = JSON.parse(raw);
    if (view.schema !== 3 || !view.apps?.length || view.source.through !== manifest.through || view.source.anchor?.payload.head_hash !== manifest.headHash) throw Error('Invalid reviewed presentation bundle');
    return matches(view) ? view : null;
  };
  let incidentHtml;
  if (manifest.incidentHtmlSha256) {
    incidentHtml = await readFile(resolve(bundleDir, 'incident.html'), 'utf8');
    if (digest(incidentHtml) !== manifest.incidentHtmlSha256) throw Error('Incident HTML changed; rebuild the MCP App');
  }
  let icons;
  if (manifest.dashboardIconSha256) {
    const icon = await readFile(resolve(bundleDir, 'activity-observer.png'));
    if (digest(icon) !== manifest.dashboardIconSha256) throw Error('Dashboard icon changed; rebuild the MCP App');
    icons = [{ src: 'data:image/png;base64,' + icon.toString('base64'), mimeType: 'image/png', sizes: ['64x64'] }];
  }
  return { html, dashboardHtml: html.replace('<html lang="ko"', '<html lang="ko" data-activity-observer-mode="dashboard"'),
    manifest, readView, incidentHtml, icons, readPublication: (through, hash) => readReviewPublication(historyDir, through, hash),
    readIcons: through => readReviewIcons(historyDir, through) };
}

export function createObserverState() {
  return { displayed: new Map(), periods: new Map(), detailed: null, detailRequests: new Map(),
    detailTransfers: new Map(), work: Promise.resolve() };
}

export function createObserverServer(bundle, finderOptions, { state = createObserverState() } = {}) {
  const icons = bundle.icons;
  // Tool metadata and text for the model follow the macOS language. Stored
  // facts use the canonical tokens, so other languages are translated for the model.
  const text = serverI18n(), s = text.s;
  const described = name => ({ title: s('tool.' + name + '.title'), description: s('tool.' + name + '.description') });
  const forModel = (value, localize) => text.locale === canonicalLocale ? value : localize(value, text);
  const server = new McpServer({ name: 'activity-observer', version: '0.4.2', ...(icons && { icons }) }, { instructions: s('server.instructions') });
  // Log-derived values for the model are cleaned and kept under `observed`.
  const observedResult = (rest, data) => {
    const { value, flagged } = guardObserved(data);
    return { ...rest, observed: value, observedNotice: s('notice.observed'), ...(flagged.length && { flagged }) };
  };
  // Results that a widget also reads keep their shape. Their strings are cleaned in place.
  const cleanedResult = data => {
    const { value, flagged } = guardObserved(data, 'result');
    return { ...value, observedNotice: s('notice.cleaned'), ...(flagged.length && { flagged }) };
  };
  const { html } = bundle;
  const uri = 'ui://activity-observer/review.html';
  const dashboardUri = 'ui://activity-observer/dashboard.html';
  // Retain only a few served views. A newly published report must never
  // reinterpret an older widget's location IDs against a different interval.
  const { displayed, periods, detailTransfers } = state;
  const serialize = work => {
    const task = state.work.catch(() => {}).then(work);
    state.work = task.then(() => {}, () => {});
    return task;
  };
  const getView = async (throughId, expectedHeadHash, expectedPublicationHash) => {
    const saved = bundle.readPublication?.(throughId, expectedHeadHash);
    const hash = saved && reviewPublicationHash(saved);
    if (expectedPublicationHash && hash !== expectedPublicationHash) throw fail('publication_mismatch');
    let legacy = bundle.view;
    if (bundle.readView && !saved) {
      try { legacy = await bundle.readView(throughId, expectedHeadHash); }
      catch (error) { if (!saved) throw error; }
    }
    const publication = saved && (!legacy || expectedPublicationHash || saved.source.through >= legacy.source.through) ? saved : null;
    const view = legacy && (!publication || legacy.source.through === publication.source.through &&
      legacy.source.anchor.payload.head_hash === publication.source.anchor.payload.head_hash) ? legacy : null;
    const source = publication?.source ?? view?.source;
    if (!source || (throughId !== undefined && source.through !== throughId) ||
        (expectedHeadHash && source.anchor.payload.head_hash !== expectedHeadHash)) throw fail('report_not_found');
    const through = source.through;
    const cached = displayed.get(through);
    if (cached && cached.publicationHash === (publication ? hash : null) && cached.view === view &&
        cached.source.anchor.payload.head_hash === source.anchor.payload.head_hash) return cached;
    const entry = { source, view, publication, report: publication?.report ?? view?.report,
      publicationHash: publication ? hash : null,
      applications: publication?.applications ?? view.apps.map(reviewApplication) };
    displayed.set(through, entry);
    if (displayed.size > 4) displayed.delete(displayed.keys().next().value);
    return entry;
  };
  const loadDetails = async (entry, programId, signal) => {
    entry.catalog ??= await readActivityCatalog(entry.source,signal);
    const [app] = await readPublishedPrograms(entry.publication,signal,programId,entry.catalog);
    const card = entry.applications.find(card=>card.id===programId);
    if (!app || !card || (card.detailHash && reviewProgramDigest(reviewDetailWithoutReferences(app),entry.publication.schema)!==card.detailHash)) throw fail('detail_mismatch');
    const views = state.detailed?.entry===entry ? state.detailed.views : new Map();
    const data=JSON.stringify(app); views.set(programId,data);
    while(views.size>1 && [...views.values()].reduce((sum,value)=>sum+Buffer.byteLength(value),0)>detailedCacheBytes) views.delete(views.keys().next().value);
    if(Buffer.byteLength(data)<=detailedCacheBytes) state.detailed={entry,views};
    return views;
  };
  const readApps = async (entry, programId, signal) => {
    if(entry.view && !entry.publication) return entry.view.apps.filter(app=>programId===undefined || app.id===programId);
    programId ??= entry.applications[0]?.id;
    if(!entry.applications.some(app=>app.id===programId)) return [];
    const cached=state.detailed?.entry===entry ? state.detailed.views.get(programId) : undefined;
    let data;
    if(cached) {
      await assertPublishedRetained(entry.publication,signal); data=cached;
    } else {
      const key=entry.publicationHash+':'+programId;
      let request=state.detailRequests.get(key);
      if(!request || request.controller.signal.aborted) {
        request={controller:new AbortController(),readers:0,finished:false};
        request.result=serialize(async()=>{
          request.controller.signal.throwIfAborted();
          const views=state.detailed?.entry===entry && state.detailed.views.has(programId) ? state.detailed.views : await loadDetails(entry,programId,request.controller.signal);
          return views.get(programId);
        }).finally(()=>{request.finished=true;if(state.detailRequests.get(key)===request)state.detailRequests.delete(key);});
        state.detailRequests.set(key,request);
      }
      request.readers++;
      let abort;
      const cancelled=new Promise((resolve,reject)=>{
        abort=()=>reject(signal.reason); signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
      });
      try { data=await Promise.race([request.result,cancelled]); }
      finally {signal?.removeEventListener('abort',abort);request.readers--;if(!request.readers&&!request.finished)request.controller.abort();}
    }
    signal?.throwIfAborted();return [JSON.parse(data)];
  };
  const reviewIcons = entry => {
    const icons = new Map(entry.view?.apps.filter(app => app.iconData).map(app => [app.id, app.iconData]));
    for (const [id, image] of bundle.readIcons?.(entry.source.through) ?? []) icons.set(id, image);
    return icons;
  };
  const cardSummary = entry => {
    const summary = reviewCardSummary(entry.source, entry.applications);
    if (entry.publication?.cards) summary.applications = entry.publication.cards;
    if (entry.publicationHash) summary.publicationHash = entry.publicationHash;
    if (entry.report?.verdict) summary.verdict = entry.report.verdict;
    return summary;
  };
  const unavailable = () => errorResult(fail('view_unavailable'));
  const resource = (resourceUri, markup, fullscreen = false) => ({
    contents: [{ uri: resourceUri, mimeType: RESOURCE_MIME_TYPE, text: markup,
      _meta: { ui: { csp: { connectDomains: [], resourceDomains: [] } },
        ...(fullscreen && { 'openai/ui': { availableDisplayModes: ['fullscreen'] } }) } }]
  });
  const dashboardHtml = bundle.dashboardHtml ?? html.replace('<html lang="ko"', '<html lang="ko" data-activity-observer-mode="dashboard"');
  registerAppResource(server, 'activity-review', uri, { description: s('resource.review') }, async () => resource(uri, html));
  registerAppResource(server, 'activity-dashboard', dashboardUri, { description: s('resource.dashboard') }, async () => resource(dashboardUri, dashboardHtml, true));
  server.registerResource('historical-activity-observer',
    new ResourceTemplate('ui://activity-observer/{filename}', { list: undefined }),
    { description: s('resource.history'), mimeType: RESOURCE_MIME_TYPE }, async value => {
      if (value.search || value.hash) throw Error('Unknown Activity Observer resource');
      const filename = value.pathname;
      if (/^\/dashboard-[0-9a-f]{16}\.html$/.test(filename)) return resource(value.href, dashboardHtml, true);
      if (/^\/review-[0-9a-f]{16}\.html$/.test(filename)) return resource(value.href, html);
      if (/^\/incident-[0-9a-f]{16}\.html$/.test(filename) && bundle.incidentHtml) return resource(value.href, bundle.incidentHtml);
      throw Error('Unknown Activity Observer resource');
    });
  registerAppTool(server, 'open_activity_dashboard', {
    title: 'Activity Observer', description: s('tool.open_activity_dashboard.description'),
    inputSchema: z.object({}).strict(), annotations: readOnly,
    ...(icons && { icons }),
    _meta: { ui: { resourceUri: dashboardUri }, 'openai/ui': { entrypoints: [{ type: 'global' }] } }
  }, async () => ({ content: [], structuredContent: { opened: true } }));
  if (bundle.incidentHtml) {
    const incidentUri = 'ui://activity-observer/incident.html';
    const incidentInput = z.object({ incidentId: z.string().regex(incidentIdPattern), revision: eventId.optional() }).strict();
    const incidentOutput = z.object({ id: z.string(), revision: eventId, severity: z.number(), createdAt: z.number(),
      reasons: z.array(z.string()), reasonCodes: z.array(z.string()).optional(), verified: z.boolean(), evidence: z.array(z.unknown()),
      coverageGap: z.object({ after: eventId, through: eventId }).optional(), timeZone: z.string().optional(),
      observedNotice: z.string().optional(), flagged: z.array(z.unknown()).optional() });
    registerAppResource(server, 'activity-incident', incidentUri, { description: s('resource.incident') }, async () => ({
      contents: [{ uri: incidentUri, mimeType: RESOURCE_MIME_TYPE, text: bundle.incidentHtml,
        _meta: { ui: { csp: { connectDomains: [], resourceDomains: [] } } } }]
    }));
    const readIncident = async ({ incidentId, revision }) => {
      try {
        const view = readIncidentView(incidentId, revision);
        // Times are shown in the Mac's zone, also when the chat is open on another device.
        return { content: [{ type: 'text', text: s('result.incident', { id: view.id, revision: view.revision }) }],
          structuredContent: { ...cleanedResult(view), timeZone: systemZone() } };
      } catch {
        return errorResult(fail('incident_unavailable'));
      }
    };
    registerAppTool(server, 'show_activity_incident', {
      ...described('show_activity_incident'),
      inputSchema: incidentInput, outputSchema: incidentOutput, annotations: readOnly,
      _meta: { ui: { resourceUri: incidentUri, visibility: ['model', 'app'] } }
    }, readIncident);
    registerAppTool(server, 'read_activity_incident_view', {
      title: s('tool.read_activity_incident_view.title'), inputSchema: incidentInput, outputSchema: incidentOutput, annotations: readOnly,
      _meta: { ui: { resourceUri: incidentUri, visibility: ['app'] } }
    }, readIncident);
    server.registerTool('list_activity_incidents', {
      ...described('list_activity_incidents'),
      inputSchema: z.object({}).strict(), outputSchema: z.object({ incidents: z.array(z.unknown()) }), annotations: readOnly
    }, async () => ({ content: [], structuredContent: { incidents: listIncidentViews() } }));
  }
  registerAppTool(server, 'show_activity_review', {
    ...described('show_activity_review'),
    inputSchema: z.object({ ...reviewReferenceFields, throughId: eventId.optional(), expectedHeadHash: sha256.optional() }).strict(),
    outputSchema: z.object({ day: z.string(), after: z.number(), through: z.number(), headHash: z.string(), records: z.number(),
      reviewedRecords: z.number(), outsideDayRecords: z.number(), dayRecords: z.record(z.string(), z.number()),
      applicationCount: z.number(), verdict: z.enum(reviewVerdicts).optional(), report: reviewReportSchema.optional(), applications: z.array(z.unknown()), publicationHash: sha256.optional(),
      observedNotice: z.string().optional(), flagged: z.array(z.unknown()).optional() }),
    annotations: readOnly,
    _meta: { ui: { resourceUri: uri, visibility: ['model', 'app'] } }
  }, async ({ throughId, expectedHeadHash, expectedPublicationHash }) => {
    try {
      const entry = await getView(throughId, expectedHeadHash, expectedPublicationHash);
      const summary = cardSummary(entry);
      const reference = `${text.referenceLabel} ${summary.through}/${summary.headHash}` + (summary.publicationHash ? `/${summary.publicationHash}` : '');
      const shown = (summary.verdict ? s('result.verdict', { verdict: summary.verdict }) + ' ' : '') +
        s('result.review', { day: summary.day, records: summary.records, reviewed: summary.reviewedRecords, through: summary.through });
      return { content: [{ type: 'text', text: shown + '\n' + reference }],
        structuredContent: { ...cleanedResult(forModel(summary, localizeCardSummary)), ...(entry.report && { report: entry.report }) } };
    } catch (error) { return errorResult(error); }
  });
  registerAppTool(server, 'read_activity_review_cards', {
    ...described('read_activity_review_cards'),
    inputSchema: z.object(reviewReferenceFields).strict(), annotations: readOnly,
    _meta: { ui: { resourceUri: uri, visibility: ['app'] } }
  }, async ({ throughId, expectedHeadHash, expectedPublicationHash }) => {
    try {
      const entry = await getView(throughId, expectedHeadHash, expectedPublicationHash);
      return { content: [], structuredContent: cardSummary(entry) };
    } catch (error) { return errorResult(error); }
  });
  registerAppTool(server, 'read_activity_review_icons', {
    ...described('read_activity_review_icons'),
    inputSchema: z.object({ ...reviewReferenceFields,
      programIds: z.array(z.string().max(1024)).min(1).max(6) }).strict(), annotations: readOnly,
    _meta: { ui: { resourceUri: uri, visibility: ['app'] } }
  }, async ({ throughId, expectedHeadHash, expectedPublicationHash, programIds }) => {
    try {
      const entry = await getView(throughId, expectedHeadHash, expectedPublicationHash);
      const icons = reviewIcons(entry);
      return { content: [], structuredContent: { icons: Object.fromEntries(programIds.filter(id => icons.has(id)).map(id => [id, icons.get(id)])) } };
    } catch { return unavailable(); }
  });
  registerAppTool(server, 'read_activity_review_view', {
    ...described('read_activity_review_view'),
    inputSchema: z.object({ ...reviewReferenceFields, offset: eventId, programId: z.string().max(1024).optional() }).strict(),
    outputSchema: z.object({ chunk: z.string(), nextOffset: eventId.nullable() }).strict(),
    annotations: readOnly,
    _meta: { ui: { resourceUri: uri, visibility: ['app'] } }
  }, async ({ throughId, expectedHeadHash, expectedPublicationHash, offset, programId }, context) => {
    try {
      const entry = await getView(throughId, expectedHeadHash, expectedPublicationHash);
      programId ??= orderPrograms(entry.applications)[0]?.id;
      const transferKey = entry.publicationHash + ':' + programId;
      let data = offset && detailTransfers.get(transferKey)?.entry === entry ? detailTransfers.get(transferKey).data : null;
      if (!data) {
        const details = await readApps(entry, programId, context.mcpReq?.signal);
        if (!details.length) throw fail('program_not_in_report');
        const icons = reviewIcons(entry);
        const apps = details.map(app => ({ ...app, iconData: icons.get(app.id) ?? app.iconData }));
        // Preserve the original program indexes used in Finder location IDs.
        data = Buffer.from(JSON.stringify({ schema: 3, source: entry.source, report: entry.report, apps,
          publicationHash: entry.publicationHash,
          ...(programId !== undefined && { applicationIndex: entry.applications.findIndex(app => app.id === programId),
            applicationCount: entry.applications.length,
            catalog: entry.applications.map(({ id, name, records, icon, review }) => ({ id, name, records, icon, review, iconData: icons.get(id) })) }) }));
      }
      if (offset >= data.length) return unavailable();
      const end = Math.min(offset + reviewChunkBytes, data.length);
      const nextOffset = end < data.length ? end : null;
      // Chunks are immutable for this report and program, so concurrent readers
      // may ask for the same offset or revisit earlier offsets safely.
      if (nextOffset !== null) {
        detailTransfers.set(transferKey, { entry, data });
        while (detailTransfers.size > 6 || [...detailTransfers.values()].reduce((n, item) => n + item.data.length, 0) > detailedCacheBytes) {
          detailTransfers.delete(detailTransfers.keys().next().value);
        }
      }
      return { content: [], structuredContent: {
        chunk: data.subarray(offset, end).toString('base64'), nextOffset
      } };
    } catch (error) { return errorResult(error); }
  });
  registerAppTool(server, 'read_activity_period_view', {
    ...described('read_activity_period_view'),
    inputSchema:periodInput.extend({periodId:periodId.optional(),offset:eventId,programId:z.string().max(1024).optional()}).strict(),annotations:readOnly,
    _meta:{ui:{resourceUri:dashboardUri,visibility:['app']}}
  }, async ({start,end,periodId:requestedId,offset,programId},context)=>{
    try {
      const signal=context.mcpReq?.signal;
      if(!requestedId) {
        if(offset || programId!==undefined) throw fail('period_list_required');
        requestedId=await serialize(async()=>{
          signal?.throwIfAborted();
          const input=openActivityPeriod(start,end);
          const source={...input,day:start,start,end,timeZone:systemZone(),through:input.anchor.payload.head_id,after:input.first?.id?input.first.id-1:0,
            firstDay:input.first?.day ?? null,collecting:input.status.collector_running,storageAsOf:input.status.heartbeat,
            storageBytes:input.status.data_bytes,storageLimit:input.status.max_data_bytes,pruned:input.status.pruned_rows};
          const catalog=await readActivityCatalog(source,signal);
          source.rowsRead=catalog.apps.reduce((n,a)=>n+a.records,0);source.dayRows=catalog.dayRows;
          const icons=bundle.readIcons?.() ?? new Map();
          const choices=catalog.apps.map(({actors,...app})=>({...app,iconData:icons.get(app.id) ?? null}));
          const bytes=Buffer.from(JSON.stringify({schema:3,source,apps:[],catalog:choices,applicationCount:choices.length}));
          const id=randomUUID();periods.set(id,{source,catalog,choices,bytes,programs:new Map()});
          while(periods.size>6)periods.delete(periods.keys().next().value);
          return id;
        });
      }
      const entry=periods.get(requestedId);
      if(!entry || entry.source.start!==start || entry.source.end!==end) throw fail('period_expired');
      if(!activityPeriodRetained(entry.source)) throw fail('period_pruned');
      let data=entry.bytes;
      if(programId!==undefined) data=await serialize(async()=>{
        signal?.throwIfAborted();
        if(entry.programs.has(programId))return entry.programs.get(programId);
        entry.catalog ??= await readActivityCatalog(entry.source,signal);
        const app=await readCatalogProgram(entry.source,entry.catalog,programId,signal,true);
        const index=entry.choices.findIndex(item=>item.id===programId);app.iconData=entry.choices[index].iconData;
        const bytes=Buffer.from(JSON.stringify({schema:3,source:entry.source,apps:[app],catalog:entry.choices,applicationIndex:index,applicationCount:entry.choices.length}));
        if(bytes.length>detailedCacheBytes)throw fail('program_too_large');
        entry.programs.set(programId,bytes);
        return bytes;
      });
      while([...periods.values()].reduce((n,p)=>n+p.bytes.length+[...p.programs.values()].reduce((m,b)=>m+b.length,0),0)>detailedCacheBytes) {
        const oldest=periods.values().next().value;
        if(periods.size>1)periods.delete(periods.keys().next().value);
        else if(oldest.programs.size>1)oldest.programs.delete(oldest.programs.keys().next().value);
        else break;
      }
      if(offset>=data.length)throw fail('offset_invalid');
      const next=Math.min(offset+viewChunkBytes,data.length);
      return {content:[],structuredContent:{periodId:requestedId,chunk:data.subarray(offset,next).toString('base64'),nextOffset:next<data.length?next:null}};
    }catch(error){return errorResult(error,{prefix:'prefix.period',limit:180});}
  });
  server.registerTool('read_selected_activity', {
    ...described('read_selected_activity'),
    inputSchema: selectionInput, annotations: readOnly
  }, async args => {
    try {
      if ((args.startHour === undefined) !== (args.endHour === undefined) || args.startHour > args.endHour) throw fail('selection_hours_invalid');
      if ((args.eventId === undefined) !== (args.eventHash === undefined)) throw fail('selection_record_invalid');
      if ((args.firstEventId === undefined) !== (args.lastEventId === undefined) ||
          args.firstEventId === 0 || args.firstEventId > args.lastEventId || args.lastEventId > args.throughId) throw fail('selection_range_invalid');
      if((args.reviewAfter===undefined)!==(args.expectedPublicationHash===undefined))throw fail('selection_reference_incomplete');
      let timeZone;
      if(args.reviewAfter!==undefined) {
        const entry=await getView(args.throughId,args.expectedHeadHash,args.expectedPublicationHash);
        timeZone=entry.source.timeZone;
        if(entry.source.after!==args.reviewAfter || args.start!==entry.source.day || args.end!==entry.source.day ||
          !entry.applications.some(app=>digest(app.id)===args.programKey) ||
          (args.firstEventId!==undefined && args.firstEventId<=args.reviewAfter))throw fail('selection_outside_report');
      }
      const { records, ...result } = readActivitySelection({ ...args, ...(timeZone && { timeZone }) });
      return { content: [], structuredContent: observedResult({ ...args, ...result }, { records }) };
    } catch (error) {
      return errorResult(error, { prefix: 'prefix.selection', limit: 180 });
    }
  });
  server.registerTool('get_program_activity', {
    ...described('get_program_activity'),
    inputSchema: z.object({ programId: z.string().max(1024), throughId: eventId.optional(),
      expectedHeadHash: sha256.optional(), expectedPublicationHash: sha256.optional() }).strict(),
    outputSchema: z.object({ day: z.string(), through: z.number(), observed: z.object({ application: z.unknown() }),
      observedNotice: z.string(), flagged: z.array(z.unknown()).optional() }),
    annotations: readOnly
  }, async ({ programId, throughId, expectedHeadHash, expectedPublicationHash }, context) => {
    try {
      const entry = await getView(throughId, expectedHeadHash, expectedPublicationHash);
      const [a] = await readApps(entry, programId, context.mcpReq?.signal);
      if (!a) return errorResult(fail('program_not_displayed'));
      const { iconData, hours, ...activity } = a;
      return { structuredContent: observedResult({ day: entry.source.day, through: entry.source.through }, { application: forModel(activity, localizeApplication) }), content: [] };
    } catch (error) { return errorResult(error); }
  });
  const sourceError = error => errorResult(error, { prefix: 'prefix.source' });
  server.registerTool('begin_activity_review', {
    ...described('begin_activity_review'),
    inputSchema: z.object({ after: eventId, previousHash: sha256 }).strict(),
    annotations: readOnly
  }, async ({ after, previousHash }) => {
    try {
      const { summary, ...review } = beginActivityReview(after, previousHash);
      return { content: [], structuredContent: observedResult(review, { summary }) };
    } catch (error) { return sourceError(error); }
  });
  server.registerTool('read_activity_events', {
    ...described('read_activity_events'),
    inputSchema: z.object({ after: eventId, previousHash: sha256, anchor: reviewAnchor }).strict(),
    annotations: readOnly
  }, async args => {
    try {
      const { events, ...page } = readActivityPage(args);
      return { content: [], structuredContent: observedResult(page, { events }) };
    }
    catch (error) { return sourceError(error); }
  });
  registerAppTool(server, 'reveal_in_finder', {
    ...described('reveal_in_finder'),
    inputSchema: z.object({ locationId: z.string().regex(/^a\d+-(e|n)\d+:\d+$/), throughId: eventId,
      expectedHeadHash: sha256.optional(), expectedPublicationHash: sha256.optional(), periodId: periodId.optional() }).strict(),
    outputSchema: z.object({ opened: z.boolean(), requestedPath: z.string(), revealedPath: z.string(), parentFallback: z.boolean() }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false, idempotentHint: true },
    _meta: { ui: { resourceUri: uri, visibility: ['app'] } }
  }, async (args, context) => {
    try {
      const period = args.periodId && periods.get(args.periodId);
      let periodView;
      if(period) {
        if(!activityPeriodRetained(period.source))throw Error('Period records were pruned');
        const index=Number(/^a(\d+)-/.exec(args.locationId)[1]);
        const programId=period.choices[index]?.id;
        if(programId===undefined)throw Error('Unknown program');
        const app=await serialize(async()=>{
          period.catalog ??= await readActivityCatalog(period.source,context.mcpReq?.signal);
          return readCatalogProgram(period.source,period.catalog,programId,context.mcpReq?.signal,true);
        });
        periodView={source:period.source,apps:[app],applicationIndex:index};
      }
      const entry = args.periodId ? (periodView && {view:periodView}) : await getView(args.throughId,args.expectedHeadHash,args.expectedPublicationHash);
      if (!entry) throw Error('Selected period is no longer available');
      if (entry.view) {
        entry.reveal ??= createFinderRevealer(entry.view, finderOptions);
        return { content: [], structuredContent: await entry.reveal(args) };
      }
      const index = Number(/^a(\d+)-/.exec(args.locationId)[1]);
      const programId = entry.applications[index]?.id;
      if (programId === undefined) throw Error('Location is not part of the review');
      const apps = await readApps(entry, programId, context.mcpReq?.signal);
      const reveal = createFinderRevealer({ source: entry.source, apps, applicationIndex: index }, finderOptions);
      return { content: [], structuredContent: await reveal(args) };
    }
    catch { return errorResult(fail('reveal_failed')); }
  });
  return server;
}
export async function startObserverServer() {
  try {
    const flags = process.argv.slice(2);
    if (flags.some(arg => !['--stdio', '--dashboard', '--check-install', '--check-bundle'].includes(arg))) throw Error('Unsupported Activity Observer arguments');
    const bundleOnly=flags.length===1 && flags[0]==='--check-bundle';
    // Preflight loads presentation artifacts without executing the old collector.
    // A running server always validates the exact installed build and isolation.
    if(!bundleOnly)checkMcpIsolation();
    const bundle = installedMcpBuild ? await loadBundle(dir, installedReviewDir) : await loadBundle();
    if (bundleOnly || flags.includes('--check-install')) return;
    const server = createObserverServer(bundle);
    await server.connect(new StdioServerTransport());
    process.once('SIGINT', () => server.close().finally(() => process.exit(0)));
    process.once('SIGTERM', () => server.close().finally(() => process.exit(0)));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await startObserverServer();
