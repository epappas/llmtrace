# Theme tokens reference (Wave 2 / Wave 3)

All tokens are defined in `src/app/globals.css` and exposed to Tailwind via `tailwind.config.ts`.

## Status tokens

| CSS variable | Tailwind class | Purpose |
|---|---|---|
| `--success` / `--success-foreground` | `bg-success text-success-foreground` | Positive / healthy state indicators |
| `--warning` / `--warning-foreground` | `bg-warning text-warning-foreground` | Degraded / caution state |
| `--info` / `--info-foreground` | `bg-info text-info-foreground` | Informational, neutral-positive |

## Severity tokens

| CSS variable | Tailwind class | Severity level |
|---|---|---|
| `--severity-critical` / `--severity-critical-foreground` | `bg-severity-critical text-severity-critical-foreground` | Critical |
| `--severity-high` / `--severity-high-foreground` | `bg-severity-high text-severity-high-foreground` | High |
| `--severity-medium` / `--severity-medium-foreground` | `bg-severity-medium text-severity-medium-foreground` | Medium |
| `--severity-low` / `--severity-low-foreground` | `bg-severity-low text-severity-low-foreground` | Low |
| `--severity-info` / `--severity-info-foreground` | `bg-severity-info text-severity-info-foreground` | Informational |

## Color rules

- Never use raw Tailwind palette classes like `bg-amber-500`, `text-red-600`, `bg-green-500` etc. for status or severity indication. Use the semantic tokens above.
- For chips and badges, use the translucent chip pattern: `bg-severity-X/15 text-severity-X border border-severity-X/30`.
  - Example: `<span className="bg-severity-critical/15 text-severity-critical border border-severity-critical/30 rounded px-2 py-0.5 text-xs">Critical</span>`
- For filled backgrounds (alert banners, toasts): `bg-success text-success-foreground`.
- Both `:root` (light) and `.dark` blocks define these tokens, so all classes adapt automatically on theme switch.
