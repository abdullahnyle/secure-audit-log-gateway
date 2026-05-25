/**
 * Main admin app Alpine.js component.
 *
 * Responsibilities:
 *  - Token validation on load; redirect to login if missing/expired
 *  - Fetch /api/logs/query with current filter+pagination state
 *  - Render the entries table reactively
 *  - Run client-side chain verification (delegated to chain.js)
 *  - Logout
 */

function adminApp() {
  return {
    // ── State ────────────────────────────────────────────────────────
    token: '',
    username: '',
    entries: [],
    loading: false,
    error: '',

    filters: {
      service: '',
      severity: '',
      event_type: '',
      user_id: '',
    },

    limit: 25,
    offset: 0,

    // Verifier state
    verifying: false,
    chainStatus: '',       // '' | 'ok' | 'broken'
    verifyMessage: '',
    verifyResults: {},     // map: log_id -> {status, expected, actual}

    // ── Lifecycle ────────────────────────────────────────────────────
    init() {
      if (!this.loadToken()) {
        window.location.href = '/admin/login.html';
        return;
      }
      this.fetchEntries();
    },

    loadToken() {
      const token = localStorage.getItem('adminToken');
      const expiresAt = parseInt(localStorage.getItem('adminTokenExpiresAt') || '0', 10);
      if (!token || !expiresAt || Date.now() >= expiresAt) {
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminTokenExpiresAt');
        return false;
      }
      this.token = token;
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        this.username = payload.sub || 'admin';
      } catch {
        this.username = 'admin';
      }
      return true;
    },

    // ── Fetching ─────────────────────────────────────────────────────
    async fetchEntries() {
      this.loading = true;
      this.error = '';
      // Reset verification state when entries change — old results no longer apply
      this.chainStatus = '';
      this.verifyMessage = '';
      this.verifyResults = {};

      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(this.filters)) {
        if (value) params.set(key, value);
      }
      params.set('limit', this.limit);
      params.set('offset', this.offset);

      try {
        const response = await fetch(`/api/logs/query?${params}`, {
          headers: { 'Authorization': `Bearer ${this.token}` },
        });

        if (response.status === 401) { this.logout(); return; }

        if (!response.ok) {
          this.error = `Server returned status ${response.status}.`;
          this.entries = [];
          return;
        }

        this.entries = await response.json();
      } catch (err) {
        this.error = 'Could not reach the server.';
        console.error(err);
        this.entries = [];
      } finally {
        this.loading = false;
      }
    },

    // ── Chain verification ───────────────────────────────────────────
    async verify() {
      if (this.entries.length === 0) return;
      this.verifying = true;
      this.chainStatus = '';
      this.verifyMessage = '';

      try {
        // verifyChain comes from chain.js, loaded before this script
        const results = await verifyChain(this.entries);

        // Index by log_id for fast row lookups
        const byId = {};
        for (const r of results) byId[r.log_id] = r;
        this.verifyResults = byId;

        const broken = results.filter(r => r.status === 'broken');
        if (broken.length === 0) {
          this.chainStatus = 'ok';
          this.verifyMessage = `All ${results.length} entries verified. The chain is intact.`;
        } else {
          this.chainStatus = 'broken';
          const ids = broken.map(b => b.log_id.slice(0, 8)).join(', ');
          this.verifyMessage = `${broken.length} entry/entries failed verification (log_id prefix: ${ids}).`;
        }
      } catch (err) {
        this.chainStatus = 'broken';
        this.verifyMessage = `Verification error: ${err.message}`;
        console.error(err);
      } finally {
        this.verifying = false;
      }
    },

    chainIcon(logId) {
      const r = this.verifyResults[logId];
      if (!r) return '<span class="chain-pending">—</span>';
      if (r.status === 'genesis') return '<span class="chain-ok" title="Genesis entry — links to chain start">⚓</span>';
      if (r.status === 'ok')      return '<span class="chain-ok" title="Hash matches">✓</span>';
      return '<span class="chain-broken" title="Hash does NOT match expected value">✗</span>';
    },

    rowClass(logId) {
      const r = this.verifyResults[logId];
      if (!r) return '';
      if (r.status === 'broken') return 'row-broken';
      return '';
    },

    get chainStatusClass() {
      if (this.chainStatus === 'ok') return 'banner-ok';
      if (this.chainStatus === 'broken') return 'banner-broken';
      return '';
    },

    // ── Filter / pagination handlers ─────────────────────────────────
    applyFilters() { this.offset = 0; this.fetchEntries(); },
    clearFilters() {
      this.filters = { service: '', severity: '', event_type: '', user_id: '' };
      this.offset = 0;
      this.fetchEntries();
    },
    nextPage() { this.offset += this.limit; this.fetchEntries(); },
    prevPage() { this.offset = Math.max(0, this.offset - this.limit); this.fetchEntries(); },

    // ── Logout ───────────────────────────────────────────────────────
    logout() {
      localStorage.removeItem('adminToken');
      localStorage.removeItem('adminTokenExpiresAt');
      window.location.href = '/admin/login.html';
    },

    // ── Formatters ───────────────────────────────────────────────────
    formatTime(iso) {
      if (!iso) return '—';
      const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
      return d.toLocaleString();
    },

    shortHash(h) {
      if (!h) return '—';
      return h.slice(0, 8) + '…' + h.slice(-6);
    },
  };
}
