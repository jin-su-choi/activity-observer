// Draws what every README image shares with the Codex desktop app: the icons,
// the navigation rail, the toolbar and the chat sidebar. Each scene page keeps
// its own chat content. Names in the sidebar are invented. Icon outlines are
// from Lucide (ISC).
const outline = {
 "house": "<path d=\"M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8\"/><path d=\"M3 10a2 2 0 0 1 .709-1.528l7-6a2 2 0 0 1 2.582 0l7 6A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z\"/>",
 "copy": "<rect width=\"14\" height=\"14\" x=\"8\" y=\"8\" rx=\"2\" ry=\"2\"/><path d=\"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2\"/>",
 "clock": "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 6v6l4 2\"/>",
 "at-sign": "<circle cx=\"12\" cy=\"12\" r=\"4\"/><path d=\"M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8\"/>",
 "ellipsis": "<circle cx=\"12\" cy=\"12\" r=\"1\"/><circle cx=\"19\" cy=\"12\" r=\"1\"/><circle cx=\"5\" cy=\"12\" r=\"1\"/>",
 "calendar": "<path d=\"M8 2v3\"/><path d=\"M16 2v3\"/><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><path d=\"M3 9h18\"/>",
 "git-compare": "<circle cx=\"18\" cy=\"18\" r=\"3\"/><circle cx=\"6\" cy=\"6\" r=\"3\"/><path d=\"M13 6h3a2 2 0 0 1 2 2v7\"/><path d=\"M11 18H8a2 2 0 0 1-2-2V9\"/>",
 "shield": "<path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\"/>",
 "arrow-left": "<path d=\"m12 19-7-7 7-7\"/><path d=\"M19 12H5\"/>",
 "arrow-right": "<path d=\"M5 12h14\"/><path d=\"m12 5 7 7-7 7\"/>",
 "panel-left": "<rect width=\"18\" height=\"18\" x=\"3\" y=\"3\" rx=\"2\"/><path d=\"M9 3v18\"/>",
 "panel-right": "<rect width=\"18\" height=\"18\" x=\"3\" y=\"3\" rx=\"2\"/><path d=\"M15 3v18\"/>",
 "folder": "<path d=\"M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z\"/>",
 "folder-open": "<path d=\"m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2\"/>",
 "chevron-down": "<path d=\"m6 9 6 6 6-6\"/>",
 "chevron-right": "<path d=\"m9 18 6-6-6-6\"/>",
 "share": "<path d=\"M12 2v13\"/><path d=\"m16 6-4-4-4 4\"/><path d=\"M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8\"/>",
 "bell": "<path d=\"M10.268 21a2 2 0 0 0 3.464 0\"/><path d=\"M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326\"/>",
 "search": "<path d=\"m21 21-4.34-4.34\"/><circle cx=\"11\" cy=\"11\" r=\"8\"/>",
 "square-pen": "<path d=\"M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7\"/><path d=\"M18.375 2.625a1 1 0 0 1 3 3l-9.013 9.014a2 2 0 0 1-.853.505l-2.873.84a.5.5 0 0 1-.62-.62l.84-2.873a2 2 0 0 1 .506-.852z\"/>",
 "plus": "<path d=\"M5 12h14\"/><path d=\"M12 5v14\"/>",
 "mic": "<path d=\"M12 19v3\"/><path d=\"M19 10v2a7 7 0 0 1-14 0v-2\"/><rect x=\"9\" y=\"2\" width=\"6\" height=\"13\" rx=\"3\"/>",
 "arrow-up": "<path d=\"m5 12 7-7 7 7\"/><path d=\"M12 19V5\"/>",
 "audio-lines": "<path d=\"M2 10v3\"/><path d=\"M6 6v11\"/><path d=\"M10 3v18\"/><path d=\"M14 8v7\"/><path d=\"M18 5v13\"/><path d=\"M22 10v3\"/>",
 "maximize-2": "<path d=\"M15 3h6v6\"/><path d=\"m21 3-7 7\"/><path d=\"m3 21 7-7\"/><path d=\"M9 21H3v-6\"/>",
 "x": "<path d=\"M18 6 6 18\"/><path d=\"m6 6 12 12\"/>",
 "minus": "<path d=\"M5 12h14\"/>",
 "grip-vertical": "<circle cx=\"9\" cy=\"12\" r=\"1\"/><circle cx=\"9\" cy=\"5\" r=\"1\"/><circle cx=\"9\" cy=\"19\" r=\"1\"/><circle cx=\"15\" cy=\"12\" r=\"1\"/><circle cx=\"15\" cy=\"5\" r=\"1\"/><circle cx=\"15\" cy=\"19\" r=\"1\"/>",
 "settings-2": "<path d=\"M14 17H5\"/><path d=\"M19 7h-9\"/><circle cx=\"17\" cy=\"17\" r=\"3\"/><circle cx=\"7\" cy=\"7\" r=\"3\"/>",
 "link": "<path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\"/><path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\"/>"
};
const drawn = {
  changes: '<rect x="3.5" y="3.5" width="17" height="17" rx="4"/><path d="M12 7.5v5M9.5 10h5M9.5 16h5"/>',
  tasks: '<circle cx="5.5" cy="7.5" r="2.3"/><circle cx="5.5" cy="16.5" r="2.3"/><path d="M11.5 7.5H21M11.5 16.5H21"/>',
  usage: '<circle cx="12" cy="12" r="9.2" opacity=".35"/><path d="M12 2.8a9.2 9.2 0 0 1 9.2 9.2"/><path d="M12 8.4 15.6 12 12 15.6 8.4 12z" fill="currentColor" stroke="none"/>',
  home: '<path d="M3 10.2a2 2 0 0 1 .7-1.5l7-6a2 2 0 0 1 2.6 0l7 6a2 2 0 0 1 .7 1.5V19a2 2 0 0 1-2 2h-3.6v-6a1 1 0 0 0-1-1h-2.8a1 1 0 0 0-1 1v6H5a2 2 0 0 1-2-2z" fill="currentColor"/>'
};
const icon = name => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (drawn[name] ?? outline[name]) + '</svg>';
const tile = '<span class="tile">' + icon('shield') + '</span>';

const projects = [
  ['security', ['Daily security review', 'Activity Observer alerts', 'Ask about my Mac']],
  ['website', ['Fix the checkout layout', 'Add a pricing page', 'Speed up image loading', 'Update the dependencies', 'Rewrite the onboarding emails'], true],
  ['api-server', ['Design rate limiting', 'Move to Postgres 17', 'Trace the slow search query']],
  ['notes', ['Weekly summary']]
];
const recents = ['Daily security review', 'Fix the checkout layout', 'Activity Observer alerts', 'Design rate limiting', 'Add a pricing page'];
const scheduled = new Set(['Daily security review']);

function rail(active) {
  const item = (id, name) => '<a' + (active === id ? ' class="on"' : '') + '>' + icon(active === id && id === 'home' ? 'home' : name) + '</a>';
  return item('home', 'house') + '<a class="pages">' + icon('copy') + '</a>' + item('scheduled', 'clock') + item('mentions', 'at-sign') + item('more', 'ellipsis') + '<hr>' +
    item('calendar', 'calendar') + item('reviews', 'git-compare') + '<a' + (active === 'observer' ? ' class="on"' : '') + '>' + tile + '</a>' +
    '<div class="bottom"><span class="usage">' + icon('usage') + '</span><span class="avatar">AK</span></div>';
}

function sidebar(active) {
  const row = (title, classes) => '<div class="sb-row ' + classes + (title === active && classes.includes('child') ? ' on' : '') + '"><span>' + title + '</span>' +
    (scheduled.has(title) ? icon('clock') : '') + '</div>';
  return '<div class="sb-head"><b>Codex</b>' + icon('chevron-down') + '<span class="tools">' + icon('bell') + icon('search') + '</span></div>' +
    '<div class="sb-row lead">' + icon('square-pen') + '<span>New chat</span></div>' +
    '<div class="sb-label">Pinned</div><div class="sb-row lead plain"><span>Release checklist</span></div>' +
    '<div class="sb-label">Projects</div>' +
    projects.map(([name, threads, more]) => '<div class="sb-group"><div class="sb-row lead">' + icon('folder-open') + '<span>' + name + '</span></div>' +
      threads.map(title => row(title, 'child')).join('') + (more ? '<div class="sb-row child more"><span>Show more</span></div>' : '') + '</div>').join('') +
    '<div class="sb-row lead plain more"><span>Show more</span></div>' +
    '<div class="sb-label">Recents</div>' + recents.map(title => row(title, 'lead plain')).join('');
}

function toolbar(view, title) {
  const button = (name, classes) => '<a class="tb-button ' + (classes ?? '') + '">' + icon(name) + '</a>';
  const lights = '<div class="lights"><i></i><i></i><i></i></div>';
  if (view === 'app') return lights + '<div class="tb-nav dim">' + icon('arrow-left') + icon('arrow-right') + '</div><div class="tb-right">' + button('panel-right') + '</div>';
  const start = lights + '<div class="tb-nav">' + icon('arrow-left') + '<span class="dim">' + icon('arrow-right') + '</span>' + icon('panel-left') + '</div><div class="tb-divider"></div>' +
    '<div class="tb-title">' + icon('folder') + '<b>' + title + '</b>' + icon('chevron-down') + '</div>';
  if (view === 'split') return start + '<div class="tb-actions">' + button('share') + button('tasks') + '</div>' +
    '<div class="tb-tab">' + tile + '<b>Activity Observer</b>' + icon('x') + '</div><div class="tb-add">' + icon('plus') + '</div>' +
    '<div class="tb-right">' + button('maximize-2', 'small') + button('panel-right', 'on') + '</div>';
  return start + '<div class="tb-right">' + button('share') + button('tasks', 'on') + button('panel-right') + '</div>';
}

const { view, title, rail: active } = document.body.dataset;
document.querySelector('.toolbar').innerHTML = toolbar(view, title);
document.querySelector('.rail').innerHTML = rail(active);
const side = document.querySelector('.sidebar');
if (side) side.innerHTML = sidebar(title);
for (const mark of document.querySelectorAll('i[data-icon]')) {
  const holder = document.createElement('span');
  holder.innerHTML = mark.dataset.icon === 'tile' ? tile : icon(mark.dataset.icon);
  const node = holder.firstElementChild;
  if (mark.className) node.setAttribute('class', ((node.getAttribute('class') ?? '') + ' ' + mark.className).trim());
  mark.replaceWith(node);
}
