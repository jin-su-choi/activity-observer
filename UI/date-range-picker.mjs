import { i18n, t } from './widget-i18n.mjs';

// "Today" is the current day in the Mac's time zone.
const localToday = () => i18n.today();
const isoDay = date => date.toISOString().slice(0, 10);
const dateOf = day => new Date(`${day}T00:00:00Z`);
const monthOf = day => dateOf(`${day.slice(0, 7)}-01`);
const moveDays = (day, count) => {
  const date = dateOf(day);
  date.setUTCDate(date.getUTCDate() + count);
  return isoDay(date);
};
let labels;
// Calendar labels follow the current display language.
function calendarLabels() {
  if (labels?.tag !== i18n.tag) labels = { tag: i18n.tag,
    month: new Intl.DateTimeFormat(i18n.tag, { timeZone: 'UTC', year: 'numeric', month: 'long' }),
    day: new Intl.DateTimeFormat(i18n.tag, { timeZone: 'UTC', dateStyle: 'full' }),
    weekday: new Intl.DateTimeFormat(i18n.tag, { timeZone: 'UTC', weekday: 'narrow' }) };
  return labels;
}

export function positionPopover(panel, point, gap = 8) {
  const { width, height } = panel.getBoundingClientRect();
  panel.style.left = `${Math.max(gap, Math.min(point.x, window.innerWidth - width - gap))}px`;
  panel.style.top = `${Math.max(gap, Math.min(point.y, window.innerHeight - height - gap))}px`;
}

export function installDateRangePicker(root, onChange) {
  const field = root.querySelector('#oi-range-field');
  const label = root.querySelector('#oi-range-label');
  const panel = root.querySelector('#oi-calendar');
  const grid = root.querySelector('#oi-calendar-days');
  const heading = root.querySelector('#oi-calendar-month');
  const hint = root.querySelector('#oi-calendar-hint');
  const week = root.querySelector('#oi-calendar-week');
  const prev = root.querySelector('#oi-calendar-prev');
  const next = root.querySelector('#oi-calendar-next');
  let range, start, month, activeDay, today;

  function setRange(value) {
    range = value;
    const dates = value.start === value.end ? value.start : `${value.start} ~ ${value.end}`;
    label.textContent = dates;
    field.setAttribute('aria-label', t('calendar.range', { dates }));
  }

  function chooseRange(value) {
    if (panel.matches(':popover-open')) panel.hidePopover();
    setRange(value);
    onChange(value);
  }

  function render(focus = false) {
    const { month: monthLabel, day: dayLabel, weekday } = calendarLabels();
    heading.textContent = monthLabel.format(month);
    // 2023-01-01 was a Sunday, the first column of the grid.
    week.replaceChildren(...Array.from({ length: 7 }, (_, index) => {
      const name = document.createElement('span');
      name.textContent = weekday.format(new Date(Date.UTC(2023, 0, 1 + index)));
      return name;
    }));
    next.disabled = isoDay(month) >= today.slice(0, 7) + '-01';
    hint.textContent = t(start ? 'calendar.pickEnd' : 'calendar.pickStart');
    const first = isoDay(month);
    const count = new Date(Date.UTC(month.getUTCFullYear(), month.getUTCMonth() + 1, 0)).getUTCDate();
    const dates = document.createDocumentFragment();
    for (let slot = 0; slot < 42; slot++) {
      const offset = slot - month.getUTCDay();
      if (offset < 0 || offset >= count) {
        dates.append(document.createElement('span'));
        continue;
      }
      const day = moveDays(first, offset);
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.day = day;
      button.disabled = day > today;
      button.tabIndex = day === activeDay ? 0 : -1;
      button.textContent = String(offset + 1);
      button.setAttribute('aria-label', dayLabel.format(dateOf(day)));
      button.setAttribute('aria-pressed', String(start ? day === start : day >= range.start && day <= range.end));
      if (day === today) button.setAttribute('aria-current', 'date');
      if (day === (start ?? range.start) || !start && day === range.end) button.dataset.edge = '';
      dates.append(button);
    }
    grid.replaceChildren(dates);
    if (focus) grid.querySelector(`[data-day="${activeDay}"]`)?.focus({ preventScroll: true });
  }

  function moveMonth(offset, focus = false) {
    const date = new Date(month);
    date.setUTCMonth(date.getUTCMonth() + offset);
    const first = isoDay(date);
    if (first > today) return;
    month = date;
    activeDay = first;
    render(focus);
  }

  field.addEventListener('click', () => {
    if (panel.matches(':popover-open')) { panel.hidePopover(); return; }
    today = localToday();
    start = undefined;
    activeDay = range.start;
    month = monthOf(activeDay);
    render();
    panel.showPopover();
    const box = field.getBoundingClientRect();
    positionPopover(panel, { x: box.right - panel.offsetWidth, y: box.bottom + 6 });
    field.setAttribute('aria-expanded', 'true');
    grid.querySelector(`[data-day="${activeDay}"]`)?.focus({ preventScroll: true });
  });
  panel.addEventListener('toggle', event => {
    if (event.newState === 'closed') field.setAttribute('aria-expanded', 'false');
  });
  prev.addEventListener('click', () => moveMonth(-1));
  next.addEventListener('click', () => moveMonth(1));
  grid.addEventListener('click', event => {
    const day = event.target.closest('button[data-day]')?.dataset.day;
    if (!day || day > today) return;
    if (!start) {
      start = activeDay = day;
      render(true);
      return;
    }
    chooseRange(day < start ? { start: day, end: start } : { start, end: day });
    field.focus({ preventScroll: true });
  });
  grid.addEventListener('keydown', event => {
    const day = event.target.dataset.day;
    if (!day) return;
    const steps = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 };
    const weekday = dateOf(day).getUTCDay();
    if (event.key === 'PageUp' || event.key === 'PageDown') {
      event.preventDefault();
      moveMonth(event.key === 'PageUp' ? -1 : 1, true);
    } else if (Object.hasOwn(steps, event.key) || event.key === 'Home' || event.key === 'End') {
      event.preventDefault();
      const target = moveDays(day, steps[event.key] ?? (event.key === 'Home' ? -weekday : 6 - weekday));
      if (target > today) return;
      activeDay = target;
      month = monthOf(target);
      render(true);
    }
  });

  function showToday() {
    const day = localToday();
    chooseRange({ start: day, end: day });
  }
  root.querySelector('#oi-today').addEventListener('click', showToday);
  showToday();
  return {
    refresh() {
      setRange(range);
      if (panel.matches(':popover-open')) render();
    }
  };
}
