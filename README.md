# Solenetec Client Portal — Secure Document Vault
> MFA-secured client portal for solar installation tracking and IRS tax credit document classification. Built entirely solo. Live at portal.solenetec.com.

**Live:** [portal.solenetec.com](https://portal.solenetec.com) · **Built by:** Robin Colocho · **Status:** Production

---

## What it does

Clients log in to track their solar installation milestones, upload financial documents (receipts, invoices, contracts), and get AI-powered IRS tax credit matching. Every uploaded file goes through a 7-layer security pipeline before Claude Vision classifies it and extracts structured data.

## Tech stack

| Layer | Technology | Role |
|-------|-----------|------|
| Database | Supabase PostgreSQL (9 tables, RLS) | All client data, documents, milestones, audit logs |
| Auth | Supabase Auth (email + TOTP MFA) | AAL1 standard session, AAL2 required for vault access |
| Storage | Supabase Storage (AWS S3, AES-256) | Encrypted document storage, signed URL downloads |
| AI Classification | Anthropic Claude Vision API | Reads receipts as base64 images, extracts IRS credit fields with confidence scores |
| File Security | VirusTotal API | Every upload scanned for malware before storage |
| Email | SendGrid | 6 branded transactional auth email templates |
| Serverless API | Cloudflare Worker (v3) | JWT verification, file upload pipeline, AI classification, admin routes |
| Hosting | Hostinger | Static portal pages at portal.solenetec.com |

## Key features

- **TOTP MFA** — Google Authenticator, Authy, 1Password supported. AAL2 required for document vault access
- **7-layer file security** — Magic byte validation · MIME whitelist · 25MB limit · VirusTotal scan · PDF content stripping · KV rate limiting (10/hr) · audit logging
- **Claude Vision classification** — Reads scanned receipts, email PDFs, and HTML-generated invoices as base64 images. Per-field confidence scores (0–100). Auto-populates high-confidence fields, flags low-confidence for manual review
- **IRS credit matching** — §25D (solar/battery), §25C (heat pumps), §30C (EV charging), §48 (commercial)
- **Real-time milestone tracker** — Design → Permit → Install → Inspection → PTO
- **9-table schema** — clients, projects, milestones, documents, contracts, payments, audit_logs, security_events, classification_edits. Row Level Security on every table.

## Production bugs diagnosed & fixed

| Bug | Root cause | Fix |
|-----|-----------|-----|
| Login broken in all browsers | Variable used before declaration — ReferenceError crashed all JS | Moved all declarations to top of script |
| File upload returning 401 | AAL2 tokens use RS256 — Worker was doing HS256 locally | Switched to Supabase /auth/v1/user API verification |
| AI classification returning 400 | Wrong field names sent to Worker | Fixed field names, upgraded to base64 Vision API |
| Supabase update failing | Column names mismatched (amount vs purchase_amount) | Fixed via schema inspection query |

## Product decisions & what I learned

- MFA enforcement at the vault level (not login level) was a deliberate UX decision — requiring MFA on every login would increase friction for routine milestone checks
- VirusTotal scanning adds ~2–4 seconds to upload time — acceptable tradeoff for a portal handling financial documents
- Per-field confidence scores rather than a single document score gives users actionable information — they know exactly which fields to verify
- Row Level Security in Supabase handles multi-tenant data isolation at the database level — eliminates an entire class of authorization bugs

---
*Built by Robin Alexander Colocho · [Didim Digital](https://didimdigital.com) · [LinkedIn](https://linkedin.com/in/rcolocho)*
