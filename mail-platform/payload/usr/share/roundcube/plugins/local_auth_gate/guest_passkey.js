(() => {
    'use strict';

    function init() {
        const button = document.getElementById('webmail-passkey-login');
        if (!button) return;
        const fallback = document.getElementById('webmail-passkey-account-login');
        const identity = document.querySelector('#login-form [name="_user"]');
        const status = document.getElementById('webmail-passkey-login-result');
        button.disabled = fallback.disabled = !window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials;

        const decode = value => {
            const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
            return Uint8Array.from(atob(base64 + '='.repeat((4 - base64.length % 4) % 4)), char => char.charCodeAt(0));
        };
        const encode = value => btoa(Array.from(new Uint8Array(value), byte => String.fromCharCode(byte)).join(''))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        async function post(step, data) {
            const result = await fetch(rcmail.url('plugin.local_auth_gate-login-' + step), {
                method: 'POST', redirect: 'error', credentials: 'same-origin', cache: 'no-store',
                headers: {'Content-Type': 'application/json', 'X-Roundcube-Request': rcmail.env.request_token},
                body: JSON.stringify(data),
            });
            const body = await result.json();
            if (!result.ok || !body.ok) throw new Error('passkey_failed');
            return body;
        }
        async function signIn(byAccount) {
            if (button.disabled) return;
            if (byAccount && !identity.value.trim()) {
                status.textContent = '登録したメールアドレスを入力してください。';
                identity.focus();
                return;
            }
            button.disabled = fallback.disabled = true;
            status.textContent = 'パスキーを確認しています。';
            try {
                const start = await post('options', byAccount ? {email: identity.value} : {});
                const key = start.publicKey;
                key.challenge = decode(key.challenge);
                key.allowCredentials = (key.allowCredentials || []).map(record => ({...record, id: decode(record.id)}));
                const credential = await navigator.credentials.get({publicKey: key});
                if (!credential) throw new Error('cancelled');
                const response = credential.response;
                const finish = await post('finish', {ceremony_id: start.ceremony_id, credential: {
                    id: credential.id,
                    rawId: encode(credential.rawId),
                    type: credential.type,
                    authenticatorAttachment: credential.authenticatorAttachment || null,
                    clientExtensionResults: credential.getClientExtensionResults(),
                    response: {
                        clientDataJSON: encode(response.clientDataJSON),
                        authenticatorData: encode(response.authenticatorData),
                        signature: encode(response.signature),
                        userHandle: response.userHandle ? encode(response.userHandle) : null,
                    },
                }});
                const redirect = new URL(finish.redirect, window.location.href);
                if (redirect.origin !== window.location.origin) throw new Error('unexpected_redirect');
                window.location.assign(redirect.href);
            } catch (_) {
                status.textContent = byAccount
                    ? 'パスキーでログインできませんでした。メールアドレスと登録済みパスキーを確認してください。'
                    : 'パスキーでログインできませんでした。メールアドレスを指定した認証も選べます。';
            } finally { button.disabled = fallback.disabled = false; }
        }
        button.addEventListener('click', () => signIn(false));
        fallback.addEventListener('click', () => signIn(true));
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, {once: true});
    else init();
})();
