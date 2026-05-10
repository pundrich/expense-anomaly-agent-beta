# Beta deployment — Expense Anomaly Agent (with Researcher role)

This folder is the **beta** version with the new Researcher role, multiple
anomaly-detection algorithms, document upload, and the data infrastructure
for system-effectiveness analytics. It deploys as a **separate Render
service** at `beta.daylight.pundrich.com`, leaving your production site at
`daylight.pundrich.com` completely untouched.

## What's in Pass 1 (this folder, ready to deploy)

* New **Researcher / Analyst** role tile (visible only to users with the
  researcher flag, or to admins).
* Researcher dashboard skeleton with five tabs: Overview, Algorithm,
  Event log, Treatments, Institutional indicators.
* Five swappable anomaly-detection algorithms — Z-score, Log Z-score,
  MAD (modified Z), IQR / Tukey fences, Per-requester baseline. The
  researcher chooses which is active.
* The algorithm name is **hidden from employees and auditors** — they
  only see "Algorithm sensitivity". Switching algorithms takes effect
  immediately for everyone.
* Document upload on every flagged card (PDF / image, max 5 MB).
  PDF text is extracted server-side and fed into the LLM prompt so the
  classifier can read receipts. Image content is stored but not
  "seen" by the text-only model.
* Audit-event log table — every override, classification, rule change,
  treatment deployment, doc upload is persisted to Postgres for the
  Pass 2 analyses.
* User-management form gains a **Researcher** checkbox alongside Admin.
* Auditor's rule-creation wizard endpoint is wired (`/api/wizard-rule`);
  the UI for it ships in Pass 2.

## What's coming in Pass 2

* The five regression / event-study tables in the Researcher dashboard
  (override-rate analysis, employee flag-risk ranking, event study
  around rule changes, parallel-trends test, indicator dashboard).
* Treatment-assignment UI: pick a target group (departments, requesters,
  random %) and apply an experimental rule.
* Auditor-facing strategy-driven rule wizard frontend.
* Mock-data generator that creates a realistic 6-month timeline of
  transactions, audit overrides, rule events, and document attachments
  so the analytics have data to work with on first deploy.

---

## Deployment steps (run from this folder)

The high-level shape is the same as production: push to a new GitHub
repo, create a second Render service, give it its own Neon database,
add a CNAME for `beta.daylight.pundrich.com`. About 20 minutes total.

### 1. Create a SECOND Neon database

Don't reuse the production database — that would mix beta users with
real ones. In Neon, click **New Project** → name it `expense-audit-beta`
→ copy the connection string.

### 2. Push to a new GitHub repo

```bash
cd "/Users/gpereirapundrich/UF Dropbox/Gabriel Pereira Pundrich/CONT_AUDIT/expense_anomaly_agent_deploy_beta"
git init
git add .
git commit -m "Initial beta deploy"
gh repo create expense-anomaly-agent-beta --public
git push -u origin main
```

### 3. Create a SECOND Render service

In Render: **New +** → **Blueprint** → connect the new
`expense-anomaly-agent-beta` repo. Render reads the `render.yaml` and
creates a service named `expense-anomaly-agent-beta`.

Set the secret env vars:
* `GROQ_API_KEY` — same key as production is fine, or a new one
  (Groq's free tier covers both at this scale)
* `DATABASE_URL` — the **new beta** Neon connection string from step 1
* `DEFAULT_ADMIN_PASSWORD` — pick a strong password

Click **Apply**. Wait ~3 minutes for the build.

### 4. Add the CNAME at GoDaddy

In Render, open the new service → **Settings** → **Custom Domains** →
add `beta.daylight.pundrich.com`. Render gives you a CNAME target
like `expense-anomaly-agent-beta.onrender.com`.

In GoDaddy DNS for `pundrich.com`, add another CNAME row:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| CNAME | `beta.daylight` | `expense-anomaly-agent-beta.onrender.com` | 1 Hour |

Wait 5–15 minutes for propagation, click **Retry Verification** on
Render, certificate provisions, done.

### 5. First login

Open `https://beta.daylight.pundrich.com`. Log in as `admin` with
the password you set in step 3. Then:

1. Click **Manage users** → tick **Researcher** when adding accounts
   that should access the Researcher dashboard.
2. Go to **Manage users → Add user** to give yourself a researcher
   account too (or tick both Admin AND Researcher on your admin
   account by editing the database directly).
3. Sign back in as the researcher account, pick the **Researcher /
   Analyst** role from the picker, switch to the **Algorithm** tab,
   and try changing the active algorithm. Employees and auditors will
   only see the sensitivity slider — they won't know which algorithm
   is in use.

## Differences vs the production codebase

| Concern             | Production (`expense-anomaly-agent`)     | Beta (`expense-anomaly-agent-beta`)         |
| ------------------- | ---------------------------------------- | ------------------------------------------- |
| Roles               | employee, auditor                         | employee, auditor, **researcher**           |
| Detection algorithm | Z-score only                             | 5 algorithms, researcher-selectable         |
| Threshold UI label  | "Z-score threshold (σ)"                   | "Algorithm sensitivity" (algo hidden)       |
| Documents on cards  | none                                     | upload + auto-load + LLM PDF reading        |
| Audit event log     | none (overrides only in localStorage)    | full server-side log in Postgres            |
| Treatments          | none                                     | API + skeleton UI (full UI in Pass 2)       |
| Database            | `expense-audit` Neon project             | `expense-audit-beta` Neon project           |
| Domain              | `daylight.pundrich.com`                  | `beta.daylight.pundrich.com`                |

Production stays live and unchanged the entire time.

## After Pass 2 is built and tested

When you're happy with the beta, the migration path to production is:

1. Test thoroughly on `beta.daylight.pundrich.com`.
2. When ready, copy the contents of `expense_anomaly_agent_deploy_beta/`
   over `expense_anomaly_agent_deploy/` (keeping the production
   `render.yaml` service name).
3. `git commit && git push` in the production repo.
4. Production redeploys automatically. (You'll need to migrate any
   beta-only data: users, rules, events. I can write a small migration
   script when we get there.)

Or just keep both running indefinitely — beta as a sandbox, production
as the stable line.
