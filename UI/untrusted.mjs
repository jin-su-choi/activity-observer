// Program names, paths, versions and device names in the log are chosen by
// the programs being observed. One of them can be written to read like an
// instruction to the agent that reviews the log. Before such text reaches a
// model it is cleaned here, and anything that reads like an instruction or
// hides characters is listed so the reader can see it was flagged.

// Control characters, zero-width and bidirectional controls, fillers, variation
// selectors and Unicode tag characters. None of them is needed to show a name.
const hidden = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB\u{E0000}-\u{E01EF}]/gu;
const lineBreaks = /[\t\n\r\u2028\u2029]+/g;

const instructionPatterns = [
  /\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any|system)\b.{0,40}\b(instruction|prompt|rule|message)s?\b/i,
  /\b(system|developer)\s*(prompt|message|instruction)s?\b/i,
  /\byou (are|must|should|will|need to)\b.{0,60}\b(assistant|agent|ai|model|claude|codex|chatgpt|gpt)\b/i,
  /\b(assistant|agent|ai|model|claude|codex|chatgpt)\b[,:]?\s+(please\s+)?(run|execute|delete|remove|send|upload|approve|allow|disable|ignore|install|open|mark|report|tell)\b/i,
  /<\/?(system|assistant|user|instructions?|tool_call|function_calls?)\b[^>]*>/i,
  /\[\/?(INST|SYSTEM|ASSISTANT)\]/i,
  /\b(do not|don't|never)\s+(tell|alert|inform|notify|warn|report)\b.{0,30}\b(user|owner|human)\b/i,
  /\b(mark|report|classify|treat)\b.{0,30}\b(as\s+)?(safe|benign|normal|trusted|expected)\b/i,
  /\b(curl|wget)\b[^|]{0,200}\|\s*(ba|z)?sh\b/i,
  /(이전|위의|앞의|모든)\s*(지시|명령|프롬프트).{0,20}(무시|잊)/,
  /시스템\s*프롬프트/,
  /(안전|정상)(하다고|이라고|으로)\s*(보고|표시|판단)/
];

export const instructionLike = text => typeof text === 'string' && instructionPatterns.some(pattern => pattern.test(text));

// Returns the text without hidden characters and on a single line.
export function cleanObservedText(value, limit = 4096) {
  const visible = value.replace(hidden, '');
  const text = visible.replace(lineBreaks, ' ');
  return { text: text.length > limit ? text.slice(0, limit) + '…' : text, hidden: visible.length !== value.length };
}

// Cleans every string in a value that was read from the log. `flagged` lists
// up to twelve strings that read like instructions or carried hidden characters.
export function guardObserved(value, name = 'observed') {
  const flagged = [];
  const flag = (field, reason, text) => {
    if (flagged.length < 12) flagged.push({ field, reason, excerpt: text.slice(0, 160) });
  };
  const walk = (node, field, depth) => {
    if (typeof node === 'string') {
      const { text, hidden: hadHidden } = cleanObservedText(node);
      if (hadHidden) flag(field, 'hidden_characters', text);
      if (instructionLike(text)) flag(field, 'instruction_like', text);
      return text;
    }
    if (depth > 12 || node === null || typeof node !== 'object') return node;
    if (Array.isArray(node)) return node.map((item, index) => walk(item, field + '[' + index + ']', depth + 1));
    return Object.fromEntries(Object.entries(node).map(([key, item]) => [key, walk(item, field + '.' + key, depth + 1)]));
  };
  return { value: walk(value, name, 0), flagged };
}
