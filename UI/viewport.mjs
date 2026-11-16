export const observerInlineHeight = 760;

export function observerViewportHeight({ fullscreen, nativeFullscreen = false, viewportHeight, visualViewportHeight,
  containerHeight, maxHeight, top = 0, bottom = 0, outerHeight, screenHeight }) {
  const positive = value => Number.isFinite(value) && value > 0 ? value : Infinity;
  const fixedHeight = positive(containerHeight);
  const limit = positive(maxHeight);
  if (!fullscreen) return Math.max(1, Math.floor(Math.min(observerInlineHeight, fixedHeight, limit)));
  let viewport = Number.isFinite(fixedHeight) ? fixedHeight : Math.min(positive(viewportHeight), positive(visualViewportHeight));
  if (!Number.isFinite(viewport)) viewport = observerInlineHeight;
  const windowHeight = Math.min(positive(outerHeight), positive(screenHeight));
  // The legacy inline visualization can have a content-sized iframe.
  if (!Number.isFinite(fixedHeight) && !nativeFullscreen && Number.isFinite(windowHeight) && viewport >= windowHeight) {
    viewport = Math.max(1, windowHeight - 96);
  }
  const available = Math.min(viewport, limit) - Math.max(0, top) - Math.max(0, bottom);
  return Math.max(1, Math.floor(available));
}
