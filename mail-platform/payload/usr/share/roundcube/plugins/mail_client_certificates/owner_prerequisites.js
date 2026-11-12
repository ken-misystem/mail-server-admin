/* Owner metadata only. Existing server authorization remains authoritative. */
"use strict";
(function (root) {
  if (root.MailOwnerPrerequisites) return;
  const validPolicy = p => !!p && ['required', 'configured', 'passkey_available', 'recovery_available'].every(k => typeof p[k] === 'boolean');
  async function read(rc, fetcher = root.fetch.bind(root)) {
    if (!rc || typeof rc.env.request_token !== 'string' || rc.env.request_token.length < 16) throw new Error('owner_metadata_unavailable');
    const url = new URL(rc.url('plugin.local_auth-owner-policy'), root.location.href);
    if (url.origin !== root.location.origin || url.username || url.password) throw new Error('owner_metadata_unavailable');
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000);
    try {
      const reply = await fetcher(url.href, {method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: {'Content-Type': 'application/json', 'X-Roundcube-Request': rc.env.request_token}, body: '{}', signal: controller.signal});
      if (!reply.ok) throw new Error('owner_metadata_unavailable');
      const text = await reply.text();
      if (text.length > 65536) throw new Error('owner_metadata_unavailable');
      const data = JSON.parse(text);
      if (data.ok !== true || !validPolicy(data.policy)) throw new Error('owner_metadata_unavailable');
      return Object.freeze({...data.policy});
    } finally { clearTimeout(timer); }
  }
  function certificateState(policy, supported) {
    if (!validPolicy(policy)) return 'unknown';
    if (!policy.passkey_available) return 'missing';
    return supported ? 'ready' : 'unsupported';
  }
  function passwordError(value) {
    if (typeof value !== 'string' || value === '') return '保護パスワードは必須です。';
    return /^[\x21-\x7e]{16,128}$/.test(value) ? '' : '保護パスワードは空白を含まない16～128文字の半角英数記号で入力してください。';
  }
  const value = {read, validPolicy, certificateState, passwordError};
  root.MailOwnerPrerequisites = Object.freeze(value);
  if (typeof module !== 'undefined') module.exports = value;
})(typeof window !== 'undefined' ? window : globalThis);
