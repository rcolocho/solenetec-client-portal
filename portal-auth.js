/**
 * portal-auth.js
 * ─────────────────────────────────────────────────────────────────
 * Drop this script into every portal HTML page (login, dashboard,
 * vault, contracts).  It handles:
 *   - Supabase client initialisation
 *   - Session detection & refresh
 *   - MFA enforcement on vault page
 *   - Sign-in, magic-link, password-reset flows
 *   - Upload with real JWT auth
 *   - Document classification API call
 *
 * Usage in each portal page:
 *   <script src="portal-auth.js"></script>
 *   <script>PortalAuth.init({ page: 'vault' });</script>
 *
 * Replace the two constants below with your real values.
 */

const SUPABASE_URL     = 'YOUR_SUPABASE_URL';    // ← replace
const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';                // ← replace (anon/public key only)
const WORKER_URL        = 'YOUR_CLOUDFLARE_WORKER_URL'; // existing worker

// ── Load Supabase JS SDK from CDN ─────────────────────────────────
(function loadSupabaseSDK() {
  if (window.supabase) return;
  const script    = document.createElement('script');
  script.src      = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js';
  script.onload   = () => { window._supabaseReady = true; document.dispatchEvent(new Event('supabase:ready')); };
  script.onerror  = () => console.error('Failed to load Supabase SDK');
  document.head.appendChild(script);
})();

// ── Wait for SDK then initialise ──────────────────────────────────
function waitForSupabase(cb) {
  if (window._supabaseReady && window.supabase) return cb();
  document.addEventListener('supabase:ready', cb, { once: true });
}

// ── PortalAuth public API ─────────────────────────────────────────
window.PortalAuth = {
  _client: null,
  _session: null,

  /** Call once per page after DOM is ready */
  async init({ page = 'dashboard' } = {}) {
    await new Promise(resolve => waitForSupabase(resolve));

    this._client = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        persistSession:    true,
        autoRefreshToken:  true,
        detectSessionInUrl: true,   // handles magic-link tokens in URL hash
        storageKey:        'solenetec_portal_session',
      }
    });

    // Listen for auth state changes
    this._client.auth.onAuthStateChange(async (event, session) => {
      this._session = session;

      if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED') {
        if (page === 'login') {
          // Check MFA status before redirecting
          const mfaOk = await this.checkMFA();
          if (mfaOk) window.location.href = 'portal-dashboard.html';
        }
      }

      if (event === 'SIGNED_OUT') {
        if (page !== 'login') window.location.href = 'portal-login.html';
      }

      if (event === 'PASSWORD_RECOVERY') {
        if (page === 'login') {
          // Show new-password screen (you can implement this UI)
          document.getElementById('view-reset-sent')?.classList.add('active');
        }
      }
    });

    const { data: { session } } = await this._client.auth.getSession();
    this._session = session;

    // Route guard: non-login pages require a session
    if (!session && page !== 'login') {
      window.location.href = 'portal-login.html';
      return;
    }

    // Vault page: require MFA verification
    if (page === 'vault' && session) {
      const mfaVerified = await this.checkMFAForVault();
      if (!mfaVerified) return; // Gate stays visible; vault content hidden
      document.getElementById('mfa-gate')?.classList.remove('show');
      document.getElementById('vault-content')?.classList.add('show');
    }

    return session;
  },

  // ── Get JWT for API calls ───────────────────────────────────────
  async getToken() {
    const { data: { session } } = await this._client.auth.getSession();
    return session?.access_token || null;
  },

  // ── Sign in with email + password ──────────────────────────────
  async signIn(email, password) {
    const { data, error } = await this._client.auth.signInWithPassword({ email, password });
    if (error) throw error;

    // After password sign-in, check if MFA is required
    if (data.session?.user?.factors?.length > 0) {
      return { requires_mfa: true, session: data.session };
    }
    return { requires_mfa: false, session: data.session };
  },

  // ── MFA: send OTP (uses Supabase TOTP or email OTP) ────────────
  async sendMFAChallenge() {
    const factors = await this._client.auth.mfa.listFactors();
    const totpFactor = factors?.data?.totp?.[0];

    if (totpFactor) {
      // TOTP app (Google Authenticator etc.)
      const { data, error } = await this._client.auth.mfa.challenge({ factorId: totpFactor.id });
      if (error) throw error;
      return { challengeId: data.id, type: 'totp' };
    }

    // Fallback: email OTP
    const { error } = await this._client.auth.signInWithOtp({
      email: this._session?.user?.email,
      options: { shouldCreateUser: false }
    });
    if (error) throw error;
    return { type: 'email_otp' };
  },

  // ── MFA: verify OTP code ────────────────────────────────────────
  async verifyMFA(code, challengeId) {
    if (challengeId) {
      // TOTP verify
      const { data, error } = await this._client.auth.mfa.verify({
        factorId: challengeId,
        challengeId,
        code
      });
      if (error) throw error;
      return data;
    }
    // Email OTP verify — uses same signInWithOtp flow
    const email = this._session?.user?.email;
    const { data, error } = await this._client.auth.verifyOtp({ email, token: code, type: 'email' });
    if (error) throw error;
    return data;
  },

  // ── Check MFA for vault (session-based with 15-min grace) ──────
  async checkMFAForVault() {
    const key       = 'vault_mfa_verified_at';
    const verified  = localStorage.getItem(key);
    const TTL_MS    = 15 * 60 * 1000; // 15 minutes

    if (verified && (Date.now() - parseInt(verified)) < TTL_MS) {
      return true; // Within grace period
    }
    return false; // Show the MFA gate
  },

  async recordVaultMFAVerified() {
    localStorage.setItem('vault_mfa_verified_at', Date.now().toString());
  },

  // ── Check if MFA is enrolled on account ────────────────────────
  async checkMFA() {
    const { data } = await this._client.auth.mfa.listFactors();
    const enrolled  = (data?.totp?.length > 0) || (data?.phone?.length > 0);
    return enrolled;
  },

  // ── Send magic link ─────────────────────────────────────────────
  async sendMagicLink(email) {
    const { error } = await this._client.auth.signInWithOtp({
      email,
      options: {
        emailRedirectTo: `${window.location.origin}/portal-dashboard.html`,
        shouldCreateUser: false  // Only existing users — no self-signup
      }
    });
    if (error) throw error;
  },

  // ── Send password reset link ────────────────────────────────────
  async sendPasswordReset(email) {
    const { error } = await this._client.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/portal-login.html`
    });
    if (error) throw error;
  },

  // ── Sign out ────────────────────────────────────────────────────
  async signOut() {
    localStorage.removeItem('vault_mfa_verified_at');
    localStorage.removeItem('vault_session');
    await this._client.auth.signOut();
    window.location.href = 'portal-login.html';
  },

  // ── Upload file through Worker (with JWT) ──────────────────────
  async uploadFile(file, projectId, docType, onProgress) {
    const token = await this.getToken();
    if (!token) throw new Error('Not authenticated');

    // Client-side pre-checks (mirror of server checks)
    const MAX_SIZE = 25 * 1024 * 1024;
    const ALLOWED  = ['application/pdf','image/jpeg','image/jpg','image/png',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];

    if (file.size > MAX_SIZE)          throw new Error(`File exceeds 25 MB limit`);
    if (!ALLOWED.includes(file.type))  throw new Error(`File type ${file.type} not allowed`);
    if (file.name.includes('..'))      throw new Error('Invalid filename');

    const formData = new FormData();
    formData.append('file', file);
    formData.append('project_id', projectId || '');
    formData.append('doc_type', docType || 'other');

    if (onProgress) onProgress(10);

    const response = await fetch(`${WORKER_URL}/portal/upload`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      body: formData
    });

    if (onProgress) onProgress(90);

    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Upload failed');
    if (onProgress) onProgress(100);

    return result;
  },

  // ── Classify document via Worker ───────────────────────────────
  async classifyDocument(fileId, extractedText) {
    const token = await this.getToken();
    if (!token) throw new Error('Not authenticated');

    const response = await fetch(`${WORKER_URL}/portal/classify`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ file_id: fileId, extracted_text: extractedText })
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Classification failed');
    return result;
  },

  // ── Fetch client's documents from Supabase ─────────────────────
  async getDocuments(filters = {}) {
    let query = this._client
      .from('documents')
      .select('*')
      .order('uploaded_at', { ascending: false });

    if (filters.project_id) query = query.eq('project_id', filters.project_id);
    if (filters.doc_type)   query = query.eq('doc_type', filters.doc_type);
    if (filters.status)     query = query.eq('classification_status', filters.status);

    const { data, error } = await query;
    if (error) throw error;
    return data;
  },

  // ── Fetch projects ──────────────────────────────────────────────
  async getProjects() {
    const { data, error } = await this._client
      .from('projects')
      .select('*, milestones(*)')
      .order('start_date', { ascending: true });
    if (error) throw error;
    return data;
  },

  // ── Fetch contracts ─────────────────────────────────────────────
  async getContracts() {
    const { data, error } = await this._client
      .from('contracts')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    return data;
  },

  // ── Save classification edit ────────────────────────────────────
  async saveClassificationEdit(documentId, fieldName, oldValue, newValue) {
    const { error } = await this._client
      .from('classification_edits')
      .insert({
        document_id: documentId,
        client_id:   this._session?.user?.id,
        field_name:  fieldName,
        old_value:   String(oldValue || ''),
        new_value:   String(newValue || ''),
        source:      'user'
      });
    if (error) throw error;
  },

  // ── Get signed URL for a document (15-min expiry) ──────────────
  async getSignedUrl(storagePath) {
    const { data, error } = await this._client.storage
      .from('portal-documents')
      .createSignedUrl(storagePath, 900); // 900 seconds = 15 min
    if (error) throw error;
    return data.signedUrl;
  },

  // ── Get current user profile ────────────────────────────────────
  async getProfile() {
    const { data, error } = await this._client
      .from('clients')
      .select('*')
      .single();
    if (error) throw error;
    return data;
  },
};
