/**
 * In-page UI: the field button and the suggestion list.
 *
 * ## Everything lives in a shadow root
 *
 * A closed shadow root gives two things that matter here:
 *
 *  1. **Style isolation.** The page's CSS cannot reach in and restyle our UI
 *     into something misleading, and our CSS cannot leak out and break the page.
 *  2. **DOM isolation.** Page script cannot query into a closed root, so it
 *     cannot read what is displayed or synthesise clicks on our buttons.
 *
 * The host element is positioned absolutely at the document level rather than
 * next to the field, because a field inside `overflow: hidden` would clip an
 * adjacent child.
 *
 * ## No secrets are rendered
 *
 * The suggestion list shows item names and usernames. A password is never
 * written into this UI - the fill happens by messaging the worker, which returns
 * the secret straight to the filler.
 */

export interface SuggestionView {
  itemId: string;
  name: string;
  username: string | null;
  confidenceLabel: string;
}

const HOST_ID = 'passm-inline-host';
const Z_INDEX = 2_147_483_000;

/**
 * Inline styles for the shadow root. Kept here so the UI is self-contained.
 *
 * The dark-theme block comes last on purpose: its rules have the same
 * specificity as the light ones, so whichever comes later wins. With it first,
 * hovering a row in dark mode painted a light background under white text.
 */
const SHADOW_STYLES = `
  :host { all: initial; }
  * { box-sizing: border-box; font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; }

  .panel {
    background: #ffffff;
    color: #0f172a;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    box-shadow: 0 12px 32px rgba(15, 23, 42, 0.18);
    overflow: hidden;
    min-width: 260px;
    max-width: 360px;
  }

  .header {
    display: flex; align-items: center; gap: 8px;
    padding: 9px 12px; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.04em; color: #64748b;
    border-bottom: 1px solid #e2e8f0;
  }
  .header .logo { width: 16px; height: 16px; flex: 0 0 auto; }

  .row {
    display: flex; align-items: center; gap: 10px; width: 100%;
    padding: 9px 12px; border: 0; background: none; cursor: pointer;
    text-align: left; color: inherit; font-size: 13px;
  }
  .row:hover, .row:focus-visible { background: #eff4ff; outline: none; }
  .row-main { min-width: 0; flex: 1; }
  .row-name { display: block; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .secondary { display: block; font-size: 11px; color: #64748b; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .mark {
    display: grid; place-items: center; width: 26px; height: 26px; flex: 0 0 auto;
    border-radius: 7px; background: #1d4ed8; color: #ffffff;
    font-size: 11px; font-weight: 700;
  }

  .prompt { padding: 14px; }
  .prompt-body { margin: 0; font-size: 12.5px; line-height: 1.45; color: #475569; }

  .link { background: none; border: 0; color: #64748b; text-decoration: underline; cursor: pointer; font-size: 11.5px; padding: 0; }
  .link:hover { color: #1d4ed8; }

  .footer { padding: 7px 12px; border-top: 1px solid #e2e8f0; }

  /* The PassM shield, sitting inside the field's right edge. */
  .field-button {
    all: initial;
    display: grid; place-items: center;
    width: 22px; height: 22px; border-radius: 6px;
    background: #eef3fd; border: 1px solid #c7d6f5;
    cursor: pointer; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.18);
    transition: box-shadow 0.15s ease, transform 0.15s ease;
  }
  .field-button:hover { box-shadow: 0 2px 8px rgba(29, 78, 216, 0.35); transform: scale(1.06); }
  .field-button .logo { width: 16px; height: 16px; }

  @media (prefers-color-scheme: dark) {
    .panel { background: #0f172a; color: #e2e8f0; border-color: #1e293b; box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5); }
    .header { border-color: #1e293b; color: #94a3b8; }
    .row:hover, .row:focus-visible { background: #1e293b; }
    .secondary { color: #94a3b8; }
    .mark { background: #2563eb; }
    .prompt-body { color: #94a3b8; }
    .link { color: #94a3b8; }
    .link:hover { color: #93b4ff; }
    .footer { border-color: #1e293b; }
  }
`;

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * The PassM shield-and-keyhole logo as inline SVG.
 *
 * Drawn rather than loaded: an image file would have to be listed in
 * `web_accessible_resources`, which lets any page probe for the extension, and
 * an `<img>` is subject to the page's own img-src policy.
 */
function logo(): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'logo');
  svg.setAttribute('aria-hidden', 'true');

  const shapes: Array<[string, Record<string, string>]> = [
    // Shield, lighter blue on the left, navy on the right, as in the icon.
    ['path', { d: 'M12 2 20 5v6.2c0 5-3.4 9.3-8 10.8-4.6-1.5-8-5.8-8-10.8V5z', fill: '#2563eb' }],
    ['path', { d: 'M12 2 20 5v6.2c0 5-3.4 9.3-8 10.8z', fill: '#0b2a6b' }],
    // Keyhole.
    ['circle', { cx: '12', cy: '10.2', r: '2.3', fill: '#ffffff' }],
    ['path', { d: 'M11.1 11.6h1.8l.9 4.6h-3.6z', fill: '#ffffff' }],
  ];
  for (const [tag, attributes] of shapes) {
    const shape = document.createElementNS(SVG_NS, tag);
    for (const [name, value] of Object.entries(attributes)) shape.setAttribute(name, value);
    svg.appendChild(shape);
  }
  return svg;
}

type Cleanup = () => void;

/** Lazily created host element and its closed shadow root. */
let shadowRoot: ShadowRoot | null = null;

function ensureShadowRoot(): ShadowRoot {
  if (shadowRoot) return shadowRoot;

  const host = document.createElement('div');
  host.id = HOST_ID;
  host.style.position = 'absolute';
  host.style.top = '0';
  host.style.left = '0';
  host.style.width = '0';
  host.style.height = '0';
  host.style.zIndex = String(Z_INDEX);

  // `closed` so page script cannot reach in via `element.shadowRoot`.
  const root = host.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = SHADOW_STYLES;
  root.appendChild(style);

  document.documentElement.appendChild(host);
  shadowRoot = root;

  return root;
}

/** Absolute document coordinates of an element, accounting for scroll. */
function documentRect(element: HTMLElement): { top: number; left: number; width: number; height: number } {
  const rect = element.getBoundingClientRect();
  return {
    top: rect.top + window.scrollY,
    left: rect.left + window.scrollX,
    width: rect.width,
    height: rect.height,
  };
}

// ---------------------------------------------------------------------------
// Field button
// ---------------------------------------------------------------------------

const fieldButtons = new WeakMap<HTMLElement, HTMLElement>();

/**
 * Attach the PassM button to a field.
 *
 * Repositioned on scroll and resize; the listeners are passive so they cannot
 * make the page janky.
 *
 * @returns a cleanup function that removes the button and its listeners.
 */
export function attachFieldButton(
  field: HTMLInputElement,
  onClick: (anchor: HTMLInputElement) => void,
): Cleanup {
  if (fieldButtons.has(field)) return () => undefined;

  const root = ensureShadowRoot();

  const button = document.createElement('button');
  button.className = 'field-button';
  button.type = 'button';
  button.appendChild(logo());
  button.title = 'Fill with PassM';
  button.setAttribute('aria-label', 'Fill with PassM');
  button.style.position = 'absolute';

  const reposition = (): void => {
    const rect = documentRect(field);
    // Inside the field's right edge, vertically centred.
    button.style.top = `${rect.top + rect.height / 2 - 11}px`;
    button.style.left = `${rect.left + rect.width - 28}px`;
    // Hide it when the field scrolls out of view rather than leaving it floating.
    const visible = field.getBoundingClientRect().height > 0;
    button.style.display = visible ? 'grid' : 'none';
  };

  button.addEventListener('mousedown', (event) => {
    // Prevent the field losing focus, which some forms treat as an abandoned edit.
    event.preventDefault();
    event.stopPropagation();
  });

  button.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    onClick(field);
  });

  root.appendChild(button);
  fieldButtons.set(field, button);
  reposition();

  window.addEventListener('scroll', reposition, { passive: true, capture: true });
  window.addEventListener('resize', reposition, { passive: true });

  const observer = new ResizeObserver(reposition);
  observer.observe(field);

  return () => {
    window.removeEventListener('scroll', reposition, { capture: true });
    window.removeEventListener('resize', reposition);
    observer.disconnect();
    button.remove();
    fieldButtons.delete(field);
  };
}

// ---------------------------------------------------------------------------
// Suggestion list
// ---------------------------------------------------------------------------

let openPanel: HTMLElement | null = null;

/** Close whatever inline panel is open. */
export function closePanel(): void {
  openPanel?.remove();
  openPanel = null;
}

/**
 * Show credential suggestions anchored to a field.
 *
 * @param onPick Called with the chosen item id. The caller asks the worker for
 *   the secret; nothing sensitive passes through this function.
 */
export function showSuggestions(
  anchor: HTMLElement,
  suggestions: SuggestionView[],
  handlers: { onPick: (itemId: string) => void; onOpenVault: () => void },
): void {
  closePanel();

  const root = ensureShadowRoot();
  const panel = document.createElement('div');
  panel.className = 'panel';
  panel.style.position = 'absolute';

  const header = document.createElement('div');
  header.className = 'header';
  header.append(logo(), suggestions.length > 0 ? 'PassM - matching logins' : 'PassM');
  panel.appendChild(header);

  if (suggestions.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'prompt';
    const message = document.createElement('p');
    message.className = 'prompt-body';
    message.textContent = 'No saved logins match this site.';
    empty.appendChild(message);
    panel.appendChild(empty);
  }

  for (const suggestion of suggestions) {
    const row = document.createElement('button');
    row.className = 'row';
    row.type = 'button';

    const mark = document.createElement('span');
    mark.className = 'mark';
    mark.textContent = suggestion.name.charAt(0).toUpperCase() || 'P';

    const main = document.createElement('span');
    main.className = 'row-main';

    const name = document.createElement('span');
    name.className = 'row-name';
    name.textContent = suggestion.name;

    const meta = document.createElement('span');
    meta.className = 'secondary';
    // Shows why this was offered, so a "same domain" guess is visible as one.
    meta.textContent = [suggestion.username, suggestion.confidenceLabel]
      .filter(Boolean)
      .join(' - ');

    main.append(name, meta);
    row.append(mark, main);

    row.addEventListener('click', (event) => {
      event.preventDefault();
      handlers.onPick(suggestion.itemId);
      closePanel();
    });

    panel.appendChild(row);
  }

  const footer = document.createElement('div');
  footer.className = 'footer';
  const openVault = document.createElement('button');
  openVault.className = 'link';
  openVault.type = 'button';
  openVault.textContent = 'Search your vault';
  openVault.addEventListener('click', () => {
    handlers.onOpenVault();
    closePanel();
  });
  footer.appendChild(openVault);
  panel.appendChild(footer);

  const rect = documentRect(anchor);
  panel.style.top = `${rect.top + rect.height + 6}px`;
  panel.style.left = `${rect.left}px`;

  root.appendChild(panel);
  openPanel = panel;

  // Dismiss on an outside click. Registered on the next tick so the click that
  // opened the panel does not immediately close it.
  setTimeout(() => {
    const dismiss = (): void => {
      closePanel();
      document.removeEventListener('click', dismiss, true);
    };
    document.addEventListener('click', dismiss, true);
  }, 0);
}

/** Remove the entire inline UI, e.g. when the vault locks. */
export function teardown(): void {
  closePanel();
  document.getElementById(HOST_ID)?.remove();
  shadowRoot = null;
}
