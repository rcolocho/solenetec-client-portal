-- ═══════════════════════════════════════════════════════════════════
-- Solenetec Client Portal — Supabase Database Schema
-- Run this entire file in Supabase Dashboard → SQL Editor
-- ═══════════════════════════════════════════════════════════════════

-- Enable UUID extension (already on in most Supabase projects)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: clients
-- One row per portal client. Links to Supabase Auth via id = auth.users.id
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS clients (
  id                  UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email               TEXT NOT NULL UNIQUE,
  full_name           TEXT NOT NULL,
  phone               TEXT,
  address             TEXT,
  city                TEXT,
  state               TEXT DEFAULT 'CA',
  zip                 TEXT,
  project_type        TEXT,           -- 'solar', 'battery', 'ev', 'heatpump', 'multi'
  project_start_date  DATE,
  hubspot_deal_id     TEXT,           -- Link back to HubSpot CRM deal
  mfa_enrolled        BOOLEAN DEFAULT FALSE,
  portal_created_at   TIMESTAMPTZ DEFAULT NOW(),
  last_login_at       TIMESTAMPTZ,
  notes               TEXT            -- Internal notes (admin only)
);

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: projects
-- A client can have multiple projects over time
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS projects (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id       UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,        -- e.g. "Solar 9.6 kW", "Battery Add-on"
  project_type    TEXT NOT NULL,        -- 'solar','battery','ev','heatpump','other'
  system_size     TEXT,                 -- e.g. "9.6 kW", "10 kWh"
  equipment       TEXT,                 -- e.g. "Enphase IQ8M + IQ 5P"
  install_address TEXT,
  contract_value  NUMERIC(10,2),
  status          TEXT DEFAULT 'planned', -- 'planned','design','permitted','install','inspection','pto','complete'
  start_date      DATE,
  completion_date DATE,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: milestones
-- Per-project milestone tracking
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS milestones (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  client_id    UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  step         INTEGER NOT NULL,         -- 1-5 (Design, Permit, Install, Inspection, PTO)
  label        TEXT NOT NULL,
  status       TEXT DEFAULT 'future',    -- 'future','active','done'
  completed_at TIMESTAMPTZ,
  notes        TEXT,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: documents
-- Every uploaded document. Storage path references Supabase Storage.
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS documents (
  id                    TEXT PRIMARY KEY,   -- fileId from worker
  client_id             UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  project_id            UUID REFERENCES projects(id) ON DELETE SET NULL,
  original_filename     TEXT NOT NULL,
  storage_path          TEXT NOT NULL UNIQUE,
  mime_type             TEXT NOT NULL,
  file_size_bytes       INTEGER,
  doc_type              TEXT DEFAULT 'other',  -- invoice,contract,permit,warranty,rebate,statement,other

  -- AI classification fields (editable by user)
  equipment_type        TEXT,
  purchase_amount       TEXT,
  purchase_date         TEXT,
  vendor_name           TEXT,
  suggested_irc_credit  TEXT,   -- 25D,25C,30C,48,179D,45L,45Q,none
  irc_credit_confirmed  TEXT,   -- User-confirmed IRC code
  document_category     TEXT,
  irc_reasoning         TEXT,
  cpa_notes             TEXT,   -- User-added notes for tax preparer

  -- Confidence scores (0-100)
  conf_vendor           INTEGER,
  conf_amount           INTEGER,
  conf_equipment        INTEGER,
  conf_irc              INTEGER,

  -- Metadata
  classification_status TEXT DEFAULT 'pending',  -- pending,ai_complete,user_confirmed
  user_confirmed_at     TIMESTAMPTZ,

  -- Security
  virus_scan_status     TEXT DEFAULT 'pending',  -- pending,clean,flagged,skipped
  virus_scan_hash       TEXT,
  virus_scan_at         TIMESTAMPTZ,

  -- Timestamps
  uploaded_at           TIMESTAMPTZ DEFAULT NOW(),
  classified_at         TIMESTAMPTZ,
  updated_at            TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: classification_edits
-- Immutable log of every change a user makes to a document's metadata
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS classification_edits (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  document_id  TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  client_id    UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  field_name   TEXT NOT NULL,       -- e.g. 'equipment_type', 'irc_credit_confirmed'
  old_value    TEXT,
  new_value    TEXT,
  source       TEXT DEFAULT 'user', -- 'user','ai','admin'
  edited_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: contracts
-- Contract records per client
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS contracts (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id        UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  project_id       UUID REFERENCES projects(id) ON DELETE SET NULL,
  agreement_number TEXT NOT NULL,
  title            TEXT NOT NULL,
  contract_value   NUMERIC(10,2),
  status           TEXT DEFAULT 'pending', -- 'pending','sent','viewed','signed','expired'
  signed_by_client_at  TIMESTAMPTZ,
  signed_by_admin_at   TIMESTAMPTZ,
  document_id      TEXT REFERENCES documents(id),  -- The signed PDF
  docusign_envelope_id TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: payments
-- Payment schedule per contract
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS payments (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id    UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  contract_id  UUID NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
  milestone    TEXT NOT NULL,
  amount       NUMERIC(10,2) NOT NULL,
  due_date     DATE,
  paid_date    DATE,
  status       TEXT DEFAULT 'upcoming', -- 'upcoming','due','paid','overdue'
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: audit_logs
-- Every significant action — uploads, downloads, sign-ins, edits
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS audit_logs (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id     UUID REFERENCES clients(id) ON DELETE SET NULL,
  action        TEXT NOT NULL,         -- 'document_uploaded','doc_downloaded','login','classification_edited' etc
  resource_type TEXT,                  -- 'document','contract','session'
  resource_id   TEXT,
  metadata      JSONB,
  ip_address    TEXT,
  user_agent    TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════
-- TABLE: security_events
-- Rejected uploads, magic byte mismatches, malware detections
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS security_events (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  client_id   UUID REFERENCES clients(id) ON DELETE SET NULL,
  event_type  TEXT NOT NULL,   -- 'rejected_mime','magic_byte_mismatch','malware_detected','rate_limit_hit'
  severity    TEXT DEFAULT 'medium', -- 'low','medium','high','critical'
  metadata    JSONB,
  resolved    BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════
-- ROW-LEVEL SECURITY (RLS)
-- Clients can ONLY see their own rows. Admin (service_role) bypasses RLS.
-- ═══════════════════════════════════════════════════════════════════

ALTER TABLE clients             ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects            ENABLE ROW LEVEL SECURITY;
ALTER TABLE milestones          ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents           ENABLE ROW LEVEL SECURITY;
ALTER TABLE classification_edits ENABLE ROW LEVEL SECURITY;
ALTER TABLE contracts           ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments            ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events     ENABLE ROW LEVEL SECURITY;

-- clients: read own row only
CREATE POLICY "clients_self_read" ON clients
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "clients_self_update" ON clients
  FOR UPDATE USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

-- projects: read/update own projects
CREATE POLICY "projects_self_read" ON projects
  FOR SELECT USING (auth.uid() = client_id);

-- milestones: read own milestones
CREATE POLICY "milestones_self_read" ON milestones
  FOR SELECT USING (auth.uid() = client_id);

-- documents: full CRUD on own documents
CREATE POLICY "documents_self_read" ON documents
  FOR SELECT USING (auth.uid() = client_id);

CREATE POLICY "documents_self_insert" ON documents
  FOR INSERT WITH CHECK (auth.uid() = client_id);

CREATE POLICY "documents_self_update" ON documents
  FOR UPDATE USING (auth.uid() = client_id)
  WITH CHECK (auth.uid() = client_id);

CREATE POLICY "documents_self_delete" ON documents
  FOR DELETE USING (auth.uid() = client_id);

-- classification_edits: insert + read own
CREATE POLICY "edits_self_read" ON classification_edits
  FOR SELECT USING (auth.uid() = client_id);

CREATE POLICY "edits_self_insert" ON classification_edits
  FOR INSERT WITH CHECK (auth.uid() = client_id);

-- contracts: read own contracts
CREATE POLICY "contracts_self_read" ON contracts
  FOR SELECT USING (auth.uid() = client_id);

-- payments: read own payments
CREATE POLICY "payments_self_read" ON payments
  FOR SELECT USING (auth.uid() = client_id);

-- audit_logs: read own logs only
CREATE POLICY "audit_self_read" ON audit_logs
  FOR SELECT USING (auth.uid() = client_id);

-- security_events: no client access (admin only via service_role)
-- No policies needed — RLS enabled but no SELECT policy = zero client access

-- ═══════════════════════════════════════════════════════════════════
-- SUPABASE STORAGE BUCKET
-- Run after creating the 'portal-documents' bucket in the dashboard
-- ═══════════════════════════════════════════════════════════════════

-- Storage policy: clients can only read files in their own folder
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'portal-documents',
  'portal-documents',
  false,                  -- NEVER public
  26214400,               -- 25 MB in bytes
  ARRAY[
    'application/pdf',
    'image/jpeg',
    'image/png',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/msword',
    'application/vnd.ms-excel'
  ]
)
ON CONFLICT (id) DO NOTHING;

-- Storage RLS: client can only access their own folder path
CREATE POLICY "storage_client_read" ON storage.objects
  FOR SELECT USING (
    bucket_id = 'portal-documents'
    AND (storage.foldername(name))[1] = 'clients'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

CREATE POLICY "storage_client_insert" ON storage.objects
  FOR INSERT WITH CHECK (
    bucket_id = 'portal-documents'
    AND (storage.foldername(name))[1] = 'clients'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

CREATE POLICY "storage_client_delete" ON storage.objects
  FOR DELETE USING (
    bucket_id = 'portal-documents'
    AND (storage.foldername(name))[1] = 'clients'
    AND (storage.foldername(name))[2] = auth.uid()::text
  );

-- ═══════════════════════════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_documents_client     ON documents(client_id);
CREATE INDEX IF NOT EXISTS idx_documents_project    ON documents(project_id);
CREATE INDEX IF NOT EXISTS idx_documents_status     ON documents(classification_status);
CREATE INDEX IF NOT EXISTS idx_audit_client         ON audit_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_created        ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_client      ON security_events(client_id);
CREATE INDEX IF NOT EXISTS idx_security_created     ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_projects_client      ON projects(client_id);
CREATE INDEX IF NOT EXISTS idx_milestones_project   ON milestones(project_id);
CREATE INDEX IF NOT EXISTS idx_contracts_client     ON contracts(client_id);
CREATE INDEX IF NOT EXISTS idx_payments_contract    ON payments(contract_id);

-- ═══════════════════════════════════════════════════════════════════
-- AUTO-UPDATE updated_at trigger
-- ═══════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_documents_updated_at
  BEFORE UPDATE ON documents
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_projects_updated_at
  BEFORE UPDATE ON projects
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_contracts_updated_at
  BEFORE UPDATE ON contracts
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
