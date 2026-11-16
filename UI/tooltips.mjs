// Presentation code owned by the app, independent of a host's injected runtime.
export function installTooltips(root) {
  const style = document.createElement('style');
  style.textContent = `.oi-tooltip{position:fixed;z-index:10000;max-width:min(320px,calc(100vw - 16px));padding:8px 12px;border-radius:12px;background:light-dark(#fff,#2e2e2e);color:light-dark(#222228,#ececf0);border:1px solid light-dark(#e7e7ed,#424246);box-shadow:0 3px 12px #0002;font:13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;text-align:center;overflow-wrap:anywhere;pointer-events:none}`;
  root.append(style);
  const tip = document.createElement('div');
  tip.className = 'oi-tooltip';tip.id = 'oi-tooltip';tip.role = 'tooltip';tip.hidden = true;
  document.body.append(tip);
  let active = null, timer;
  const hide = () => { clearTimeout(timer);active?.removeAttribute('aria-describedby');active = null;tip.hidden = true; };
  const show = element => {
    if (!element || element === active) return;
    hide();active = element;
    timer = setTimeout(() => {
      if (!active?.isConnected) return hide();
      tip.textContent = active.dataset.tooltip;
      tip.style.colorScheme = getComputedStyle(root).colorScheme;
      tip.hidden = false;active.setAttribute('aria-describedby', tip.id);
      const rect = active.getBoundingClientRect(), size = tip.getBoundingClientRect();
      const top = rect.top - size.height - 8;
      tip.style.top = Math.max(8, Math.min(innerHeight - size.height - 8, top >= 8 ? top : rect.bottom + 8)) + 'px';
      tip.style.left = Math.max(8, Math.min(innerWidth - size.width - 8, rect.left + rect.width / 2 - size.width / 2)) + 'px';
    }, 180);
  };
  root.addEventListener('pointerover', e => show(e.target.closest('[data-tooltip]')));
  root.addEventListener('pointerout', e => { if (active && !active.contains(e.relatedTarget)) hide(); });
  root.addEventListener('focusin', e => show(e.target.closest('[data-tooltip]')));
  root.addEventListener('focusout', hide);
  root.addEventListener('scroll', hide, true);
  window.addEventListener('resize', hide);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') hide(); });
}
