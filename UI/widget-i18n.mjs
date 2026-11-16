import { applyStaticText as fillStaticText, createI18n, resolveLocale } from './i18n.mjs';

// The widget language follows the host. Before the host answers, and for hosts
// that send no locale, it follows the embedded browser.
const browserLanguages = () => [...(navigator.languages ?? []), navigator.language];
let zone;
export let i18n = createI18n(resolveLocale(browserLanguages()));
export const t = (key, params) => i18n.t(key, params);

// Returns true when the display language changed.
export function useHostLocale(tag) {
  const locale = resolveLocale(tag, browserLanguages());
  if (locale === i18n.locale) return false;
  i18n = createI18n(locale, zone);
  return true;
}

// Views carry the Mac's time zone. Returns true when the display zone changed.
export function useReviewZone(timeZone) {
  if (typeof timeZone !== 'string' || !timeZone || timeZone === zone) return false;
  zone = timeZone;
  i18n = createI18n(i18n.locale, zone);
  return true;
}

export const applyStaticText = root => fillStaticText(root, i18n);

// The server sends an error code for the widget and text for hosts that drop it.
export function toolFailure(result, fallback) {
  const failure = result.structuredContent?.error;
  const code = typeof failure?.code === 'string' ? failure.code : undefined;
  const error = Error((code && i18n.error(code, failure.params)) ||
    result.content?.find(item => item.type === 'text')?.text || i18n.t(fallback));
  error.code = code;
  return error;
}
