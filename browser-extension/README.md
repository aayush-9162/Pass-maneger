# PassM Browser Extension

Chrome Manifest V3, React + TypeScript, built with Vite.

---

## Build and load

```bash
cp .env.example .env      # VITE_API_URL must match manifest host_permissions
npm run build             # -> dist/
```

1. Open `chrome://extensions`, enable **Developer mode**.
2. **Load unpacked** → select `dist/`.
3. Copy the extension id Chrome assigns and add it to `backend/.env`:
   ```
   CORS_ALLOW_EXTENSION_ORIGINS=<extension-id>
   ```
   Restart the API. Without this the browser blocks every request the worker
   makes.

Requires Chrome 114+ for the side panel API.

**Changing the server address.** `VITE_API_URL` is only the default. If the
server's IP changes, triple-click the small server address at the bottom of the popup
or side panel and enter the new one. It is saved in
`chrome.storage.local` and kept until changed again; Chrome asks once for
permission to reach the new address.

---

## What it does

| Feature | Where |
| --- | --- |
| Sign in, session refresh, vault unlock | service worker |
| Vault sync and local search index | service worker |
| Autofill, inline field button | content script |
| Login / signup / change-password detection | content script |
| Quick search, favourites, recent, generator | popup |
| Full vault browser, settings | side panel |
| Fill, copy, generate | context menu |
| Clipboard auto-clear | offscreen document |

Site adapters cover **Google, Microsoft, Amazon, GitHub, Facebook and LinkedIn**;
everything else uses the generic detector.

---

## Structure

```
popup.html / sidepanel.html / offscreen.html   entry documents
public/manifest.json                           MV3 manifest, copied verbatim
public/content.css                             styles the shadow host only

src/background/
  service-worker.ts    message router, auth session, fill
  vault-session.ts     item index and password fetches (read-only)
  clipboard.ts         offscreen copy + alarm-driven auto-clear
  context-menus.ts     right-click menu

src/content/
  autofill.ts          entry: detection, buttons, capture, fill
  form-detector.ts     login / signup / change-password classification
  site-adapters.ts     per-provider selectors and multi-step flows
  inline-ui.ts         shadow-DOM button, suggestions, prompts
  filler.ts            framework-safe value setting

src/popup/ src/sidepanel/ src/ui/              React surfaces
src/lib/                                       api, storage, messages, settings, uri-match
src/offscreen/                                 clipboard document
```

Three Vite passes, because the output formats are incompatible:

| Config | Entries | Format | Why |
| --- | --- | --- | --- |
| `vite.config.ts` | popup, side panel, offscreen, background | ES modules | MV3 supports module workers and pages |
| `vite.content.config.ts` | content script | IIFE | Content scripts are classic scripts; `import` is unavailable |

---

## Security design

**All privileged work happens in the service worker.** The popup is destroyed
whenever it loses focus. If it owned the session, a refresh interrupted halfway
would leave the client holding a token the server already rotated — which the API
correctly treats as replay and answers by revoking the session.

**The content script is trusted with almost nothing.** It runs on every page the
user visits, including hostile ones, so it never holds the tokens, the item
index, or any credential it was not just handed for a fill the user clicked. The
worker enforces this: messages arriving with a `sender.tab` are restricted to a
four-message allow-list, and a `REQUEST_FILL` naming an item is re-checked
against the requesting page's URL before any secret is released.

**The index holds no secrets.** After sign-in the worker lists every vault once and
stores names, usernames and URIs. Passwords are fetched per item, at the moment
of use. A compromise of extension storage yields the list of sites the user has
accounts on — bad — rather than the accounts themselves.

**The index lives in `chrome.storage.session`.** Memory-backed, never written to
disk, cleared when the browser closes, and pinned to `TRUSTED_CONTEXTS` so
content scripts cannot read it. Module variables would be the obvious
alternative, but MV3 suspends the worker after ~30 seconds and the list would be
fetched again all day. Sign-in tokens live in `local` so a browser restart
stays signed in; signing out erases them.

**Credential matching refuses substring matches.** `paypal.com.evil.tld` contains
`paypal.com`, and any implementation matching on `includes()` leaks the
credential. Matching reduces both hosts to a registrable domain (with multi-part
suffixes like `co.uk` handled) and compares those. Cross-domain sign-in — Office
at `login.microsoftonline.com` — is handled by a curated family list rather than
by loosening the rule for everyone.

**The inline UI is a closed shadow root.** Page CSS cannot restyle it into
something misleading, and page script cannot query into it or synthesise clicks.

**Autofill is off by default.** Automatic filling is what makes clickjacking and
hidden-form attacks worth attempting, so it is opt-in.

**The clipboard is treated as hostile.** Any application can read it and some
platforms sync it between devices, so every copy schedules its own erasure —
driven by `chrome.alarms`, because a `setTimeout` in a suspended worker would
never fire and the password would sit there indefinitely.

---

## Form detection

No single signal is reliable, so candidates are scored on several:

1. `autocomplete` tokens (`current-password`, `new-password`, `username`) —
   decisive when present.
2. Password field count and order.
3. Text near the form; button labels and headings.
4. URL path.

Login vs everything else is the classification that matters: autofill only
targets login forms.

Forms without a `<form>` element are handled by walking up a bounded number of
levels from each password field — now the norm in single-page apps.

---

## Permissions

| Permission | Why |
| --- | --- |
| `storage` | Session state in `chrome.storage.session`; settings and device id in `local` |
| `alarms` | Token refresh, vault auto-lock and clipboard clear, all of which must survive worker suspension |
| `activeTab`, `scripting` | Fill into the tab the user is looking at, after they act |
| `contextMenus` | Right-click fill, copy and generate |
| `sidePanel` | Vault browser beside the page |
| `clipboardWrite`, `offscreen` | A service worker has no DOM and cannot reach the clipboard; a short-lived offscreen document performs the write |
| `tabs` | Read the active tab's URL to match entries. Not used for tracking — nothing is transmitted |
| `host_permissions` | The PassM API origin **only** — deliberately not a wildcard |

Change `host_permissions` in `public/manifest.json` to your deployed API before
packing, and keep `VITE_API_URL` in step with it.

---

## Known limits

- **Sign-in is Google only**, through Chrome's `identity` window. The OAuth
  client must list `https://<extension-id>.chromiumapp.org/` as an authorised
  redirect URI. The popup usually closes while Google's window has focus; the
  sign-in completes in the background and the popup reopens signed in.
- **Lock signs out.** The server releases passwords to any live session, so
  reopening a locked vault takes a fresh Google sign-in.
- **Read-only.** The extension fills and copies passwords; it never creates or
  changes one, and the server refuses writes from it. Adding and editing
  passwords is for administrators, in the console.
- **TOTP codes are stored and filled but not generated.** The secret is fetched
  and available; generating the rolling code is a later phase.
