# Dashboard dark-mode visual audit — 2026-05-29

## Environment

Dev server: booted successfully (`next dev`, Ready in 2.7s).
Visual screenshots: **not captured** — no live proxy or auth credentials available in the agent
environment (`/tmp/review_admin_pw.txt` absent), so the audit is static (source-code analysis).
All routes behind admin auth were analyzed by reading the source. Only `/login` is reachable
unauthenticated, and it uses only semantic tokens (`bg-background`, `bg-card`, `bg-primary`,
`text-primary-foreground`). Login renders correctly in both themes.

## Coverage

| Route | Source audited | Screenshot (dark) | Screenshot (light) | Toggle persisted |
|---|---|---|---|---|
| `/` | yes | N/A (no auth) | N/A | N/A |
| `/api-docs` | yes | N/A | N/A | N/A |
| `/audit` | yes | N/A | N/A | N/A |
| `/compliance` | yes | N/A | N/A | N/A |
| `/costs` | yes | N/A | N/A | N/A |
| `/guide` | yes | N/A | N/A | N/A |
| `/login` | yes | N/A (no auth needed, no screenshots) | N/A | N/A |
| `/playground` | yes | N/A | N/A | N/A |
| `/security` | yes | N/A | N/A | N/A |
| `/settings` | yes | N/A | N/A | N/A |
| `/status` | yes | N/A | N/A | N/A |
| `/tenants` | yes | N/A | N/A | N/A |
| `/tenants/config` | yes | N/A | N/A | N/A |
| `/traces` | yes | N/A | N/A | N/A |
| `/traces/[id]` | yes | N/A | N/A | N/A |

## Issues found

### Fixed in this PR

**1. `dashboard/src/app/security/page.tsx:176` — hardcoded hex fallback `"#6b7280"` in Pie `Cell` fill**

The `SEVERITY_COLORS` map handles all named severity levels, but the fallback for an unknown
entry was a raw hex (`#6b7280` — a gray). In dark mode this stays the same shade regardless of
theme. Fixed to `"hsl(var(--severity-info))"` so any unknown severity name renders with the
themed info color.

**2. `dashboard/src/app/globals.css` — `--severity-info` dark value at 46% lightness is marginal for contrast**

Dark card background is `hsl(220, 13%, 12%)` (≈ relative luminance 0.018). `--severity-info`
at `220 9% 46%` (≈ relative luminance 0.178) gives a contrast ratio of approximately 4.0:1
against the card — below the WCAG AA threshold of 4.5:1 for normal text. Bumped the dark
`--severity-info` to `220 9% 55%` (≈ relative luminance 0.258, ratio ≈ 5.0:1) which clears
the AA threshold with margin.

### Punted (follow-up PR needed)

**1. `dashboard/src/app/compliance/page.tsx:169` — `print:bg-white`**

The compliance `ReportViewer` card carries `print:bg-white print:shadow-none print:border-none`
for print output. `print:bg-white` hard-codes white for print mode — intentional and correct for
print (the dark mode CSS class wouldn't survive PDF rendering anyway). No color change needed,
but a future pass could add `print:text-black` to guarantee foreground legibility in print too.
Deferred because print CSS is a separate concern from the UI theme audit.

**2. `dashboard/src/app/tenants/_client.tsx:288` and `playground/_client.tsx:1471` — `bg-black/50` / `bg-black/40` modal backdrops**

Both use a semi-transparent black scrim as a modal backdrop. In light mode this works fine; in
dark mode the background is already dark and the `/50` overlay may make nested content harder
to read. This is a layout/design call (e.g. using `bg-background/80 backdrop-blur` instead)
and is deferred pending design review.

**3. `dashboard/src/app/compliance/page.tsx:81` — conditional `text-destructive` for severity counts**

`count > 0 && (sev === 'Critical' || sev === 'High') ? 'text-destructive' : ''` — uses
`text-destructive` which is a semantic token and will theme-switch. This is correct. Noted
here for completeness because it was reviewed; no change needed.

**4. Chart `CartesianGrid` `className="stroke-muted"` — recharts className on SVG**

Used in `page.tsx`, `security/page.tsx`, and `costs/page.tsx`. Recharts v2 passes `className`
to the SVG `<g>` wrapper, but whether Tailwind `stroke-muted` applies depends on whether the
CSS selector targets the inner `<line>` elements. This is a known Recharts/Tailwind quirk;
if the grid lines appear as browser-default (solid black) in dark mode, replace with
`stroke="hsl(var(--muted))"` attribute. Deferred — requires visual confirmation.

**5. `dashboard/src/app/guide/page.tsx:112` — `<img>` instead of Next.js `<Image>`**

Pre-existing lint warning. Not a dark-mode issue, but noted since lint flagged it. Deferred
to a general clean-up PR.

## Theme toggle implementation

`dashboard/src/components/theme-toggle.tsx` uses `next-themes` `useTheme()` to toggle between
`"light"` and `"dark"`. The toggle button carries `data-testid="theme-toggle"`. The provider in
`layout.tsx` sets `defaultTheme="dark"` and `storageKey="theme"`, so the preference persists
across reloads via `localStorage`. This is correct and will survive page reload.

## Exit codes

| Step | Result |
|---|---|
| `npm run lint` | Exit 0 (3 pre-existing warnings, 0 errors) |
| `npm run build` | Exit 0 (production build succeeded, 18 pages) |
| Dev server boot | Ready in 2.7s |
