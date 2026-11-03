# PassM Web Console

React 19, Vite, React Router, TypeScript, Tailwind CSS, Shadcn UI.

---

## Run

```bash
cp .env.example .env.local     # VITE_API_URL=http://localhost:4000/api/v1
npm run dev                    # http://localhost:3000
npm run build                  # typecheck, then a static build in out/
```

The API must be running, and `CORS_ORIGINS` in `backend/.env` must include
`http://localhost:3000` — requests are credentialed, so a wildcard origin is not
an option.

---

## Structure

```
index.html                document shell; loads public/theme-init.js before paint
src/main.tsx              entry point
src/router.tsx            route table; every page is lazy-loaded
src/layouts/
  root-layout.tsx         ThemeProvider + AuthProvider
  dashboard-layout.tsx    auth guard + app shell
  admin-layout.tsx        Advanced-area sidebar
src/pages/                one file per route (pages/admin/users.tsx = /admin/users)
src/components/ui/        Shadcn primitives
src/lib/                  API client, auth context, device identity, formatting
```

---

## Design notes

**The access token lives in a module variable, never in web storage.** Anything
in `localStorage` is readable by any script on the page, so one XSS flaw would
hand an attacker a working token. In memory it dies with the tab, and a reload
silently recovers a new one from the httpOnly refresh cookie — which this code
cannot read at all.

**Refresh is single-flight.** A page that fires several requests at once will hit
several 401s at once. Because the API rotates refresh tokens and detects replay,
letting each retry refresh independently would revoke the session. `refreshSession`
collapses concurrent attempts into one.

**Route protection is client-side, and that is not the real control.** The refresh
console is static files with no server of its own to make an authorization
decision. Redirects here are for user experience; the
API rejects unauthorized requests regardless of what the UI renders.

**Permission checks gate rendering, not access.** `hasPermission` decides which
navigation links and action buttons to show, resolved from the role through the
same shared matrix the API uses. Hiding a button is never what keeps anyone out.

**Sign-in is Google's button.** `lib/google-identity.ts` loads Google Identity
Services and hands the ID token to `POST /auth/google`; the client id comes from
the API, not the build. The step-up dialog uses the same button with the
server's challenge nonce, so its token is good for that one confirmation only.

**Passwords are fetched one at a time.** The Passwords page lists names,
usernames and sites; revealing or copying asks the server for that one
password (`GET .../items/:itemId/secret`), which audits it. Nothing is
encrypted or decrypted in the browser, and nothing is cached. The idle sign-out
(`lib/idle-context.tsx`) follows the administrator's policy.

---

## Design system

Colours are HSL triples in CSS custom properties (`src/globals.css`), so
components use semantic names (`bg-background`, `text-muted-foreground`) and dark
mode is one variable block rather than conditional classes throughout.

To add a Shadcn component, follow the existing files in `src/components/ui/` —
`components.json` is configured for `npx shadcn@latest add <component>`.

---

## Security headers

The dev server (`vite.config.ts`) sets CSP, `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy` on every response.
In production the console is static files, and the API applies the equivalent
policy when it serves them (`webContentSecurityPolicy()` in the backend).
`connect-src` is pinned to the single API origin, so the console cannot be made
to talk to anywhere else.

The production `script-src` has no `'unsafe-inline'`: the build emits no inline
script, and the pre-paint theme script is a file. The dev server keeps it only for
the React refresh preamble Vite injects.
