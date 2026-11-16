// Days and hours follow the Mac's own time zone. The collector writes each
// record's day in that zone, and the server and the widgets use the same one.
let current;
export function systemZone() {
  // Long-lived services re-read the zone once a minute, so a move is noticed.
  const now = Date.now();
  if (!current || now - current.at > 60000) {
    let timeZone = 'UTC';
    try { timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { /* Keep UTC. */ }
    current = { at: now, timeZone };
  }
  return current.timeZone;
}

export function isTimeZone(value) {
  if (typeof value !== 'string' || !value || value.length > 64) return false;
  try { new Intl.DateTimeFormat('en-US', { timeZone: value }); return true; } catch { return false; }
}

const clocks = new Map();

// Converts log timestamps to the local hour and day of one time zone.
export function zoneClock(timeZone = systemZone()) {
  let clock = clocks.get(timeZone);
  if (clock) return clock;
  const format = new Intl.DateTimeFormat('en-US', { timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit',
    day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const offsets = new Map();
  // Offsets change only at zone transitions, so one lookup per quarter hour is enough.
  const offset = seconds => {
    const slot = Math.floor(seconds / 900);
    let value = offsets.get(slot);
    if (value === undefined) {
      const parts = Object.fromEntries(format.formatToParts(new Date(slot * 900000)).map(part => [part.type, Number(part.value)]));
      value = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) / 1000 - slot * 900;
      if (offsets.size >= 8192) offsets.clear();
      offsets.set(slot, value);
    }
    return value;
  };
  const local = seconds => new Date((seconds + offset(seconds)) * 1000);
  clock = { timeZone, hour: seconds => local(seconds).getUTCHours(), day: seconds => local(seconds).toISOString().slice(0, 10) };
  clocks.set(timeZone, clock);
  return clock;
}
