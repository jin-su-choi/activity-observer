import { attachmentNotePattern } from './i18n.mjs';
import { t } from './widget-i18n.mjs';
import { cleanObservedText } from './untrusted.mjs';

const annotationId = 'activity-observer/annotationId';
const annotationNote = 'activity-observer/note';
const contextKey = 'openai/modelContext';

export function activityAttachmentKey(scope) {
  if (scope.eventId !== undefined) return `event:${scope.eventId}:${scope.eventHash}`;
  return JSON.stringify([scope.throughId, scope.expectedHeadHash, scope.programKey, scope.category,
    scope.start, scope.end, scope.startHour, scope.endHour, scope.firstEventId, scope.lastEventId,scope.reviewAfter,scope.expectedPublicationHash]);
}

function uniqueTitle(title, content) {
  const titles = new Set(content.map(block => block._meta?.['openai/group']?.title));
  if (!titles.has(title)) return title;
  let number = 2;
  while (titles.has(`${title} (${number})`)) number++;
  return `${title} (${number})`;
}

export function createActivityAttachments(app, onChange) {
  let content = [];
  let pending = false, queuedContext, ownUpdateId;

  function receive(context) {
    if (!Object.hasOwn(context, contextKey)) return;
    const state = context[contextKey];
    if (pending) { queuedContext = state; return; }
    if (ownUpdateId && state?.updateId === ownUpdateId) return;
    content = (state?.content ?? []).filter(block => block?.type === 'text' && typeof block._meta?.[annotationId] === 'string');
    onChange();
  }

  async function toggle(scope, label, comment, isRecord) {
    const key = activityAttachmentKey(scope);
    // The label carries a program name, which the observed program chose.
    const title = (label && cleanObservedText(String(label), 160).text) || t(isRecord ? 'attach.recordTitle' : 'attach.rangeTitle');
    const block = {
      type: 'text',
      text: t('attach.text', { record: isRecord, scope: JSON.stringify(scope), comment }),
      _meta: { [annotationId]: key, [annotationNote]: comment ?? '', 'openai/title': t(isRecord ? 'attach.recordTitle' : 'attach.annotationTitle'), 'openai/group': { title } }
    };
    const caps = app.getHostCapabilities() ?? {};
    if (!caps.updateModelContext) {
      if (!caps.experimental?.['openai/message'] || !caps.message) throw Error(t('attach.noChat'));
      const result = await app.sendMessage({ role: 'user', content: [{ type: 'text', text: block.text }],
        _meta: { 'openai/message': { target: 'new', send: false } } });
      if (result.isError) throw Error(t('attach.draftFailed'));
      return 'draft';
    }
    if (pending) throw Error(t('attach.busy'));
    const wasAttached = content.some(item => item._meta[annotationId] === key);
    const retained = content.filter(item => item._meta[annotationId] !== key);
    const remove = isRecord && wasAttached;
    if (!remove) block._meta['openai/group'].title = uniqueTitle(title, retained);
    const updated = remove ? retained : [...retained, block];
    pending = true;
    try {
      const result = await app.updateModelContext({ content: updated });
      if (result?.isError) throw Error(t('attach.failed'));
      ownUpdateId = result?._meta?.[contextKey]?.updateId;
      content = updated;
      onChange();
      return remove ? 'removed' : 'attached';
    } finally {
      pending = false;
      if (queuedContext !== undefined) {
        const state = queuedContext;
        queuedContext = undefined;
        receive({ [contextKey]: state });
      }
    }
  }

  function find(scope) {
    const key = activityAttachmentKey(scope);
    return content.find(block => block._meta[annotationId] === key);
  }

  const comment = scope => {
    const block = find(scope);
    const note = block?._meta[annotationNote];
    return typeof note === 'string' ? note : block?.text.split(attachmentNotePattern)[1] ?? '';
  };
  return { receive, toggle, has: scope => Boolean(find(scope)), comment };
}
