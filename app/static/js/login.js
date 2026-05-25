/**
 * Login form Alpine.js component.
 *
 * Posts credentials to /api/admin/login. On success, stores the JWT
 * in localStorage and redirects to /admin/. On failure, shows an
 * inline error message.
 */
function loginForm() {
  return {
    username: '',
    password: '',
    loading: false,
    error: '',

    async submit() {
      this.error = '';
      this.loading = true;

      try {
        const response = await fetch('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: this.username,
            password: this.password,
          }),
        });

        if (!response.ok) {
          // 401 from our login route returns { detail: "..." }.
          // Other failures (500, network) we treat generically.
          if (response.status === 401) {
            const body = await response.json().catch(() => ({}));
            this.error = body.detail || 'Invalid credentials.';
          } else {
            this.error = `Server error (status ${response.status}).`;
          }
          return;
        }

        const data = await response.json();

        // Persist the token and its expiry so the main UI can check
        // it before making requests, and redirect to login if expired.
        localStorage.setItem('adminToken', data.access_token);
        localStorage.setItem(
          'adminTokenExpiresAt',
          String(Date.now() + data.expires_in * 1000),
        );

        // Drop the password from memory (the input element will be
        // destroyed when we navigate away, but being explicit is cheap).
        this.password = '';

        window.location.href = '/admin/';
      } catch (err) {
        // Network failure, CORS error, etc.
        this.error = 'Could not reach the server. Is it running?';
        console.error(err);
      } finally {
        this.loading = false;
      }
    },
  };
}
