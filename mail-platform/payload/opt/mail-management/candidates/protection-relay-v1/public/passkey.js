(function () {
    'use strict';
    const scope = document.getElementById('admin-settings');
    if (!scope) return;
    scope.querySelectorAll('[data-receiving-preview]').forEach(output => {
        const form = output.closest('form'), input = form.querySelector('[name="local_part"]');
        const domain = form.querySelector('[name="domain_id"]');
        const render = () => { output.textContent = input.value ? '登録先: ' + input.value.trim().toLowerCase().replace(/\./g, '') + '@' + (domain.selectedOptions[0]?.textContent || '') : ''; };
        input.addEventListener('input', render); domain.addEventListener('change', render); render();
    });
}());
(function () {
    'use strict';
    const scope = document.getElementById('admin-passkey');
    if (!scope) return;
    const result = document.getElementById('admin-passkey-result');
    const register = document.getElementById('admin-passkey-register');
    const retry = document.getElementById('admin-passkey-retry');
    const enrollment = document.getElementById('admin-passkey-enrollment');
    let busy = false;
    function decode(value) {
        const s = value.replace(/-/g, '+').replace(/_/g, '/');
        return Uint8Array.from(atob(s + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0)).buffer;
    }
    function encode(value) {
        let s = '';
        new Uint8Array(value).forEach(b => { s += String.fromCharCode(b); });
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function options(key, kind) {
        key.challenge = decode(key.challenge);
        if (kind === 'register') key.user.id = decode(key.user.id);
        const name = kind === 'register' ? 'excludeCredentials' : 'allowCredentials';
        key[name] = (key[name] || []).map(c => ({ ...c, id: decode(c.id) }));
        return key;
    }
    function response(c, kind) {
        const r = { clientDataJSON: encode(c.response.clientDataJSON) };
        if (kind === 'register') {
            r.attestationObject = encode(c.response.attestationObject);
            r.transports = typeof c.response.getTransports === 'function' ? c.response.getTransports() : [];
        } else {
            r.authenticatorData = encode(c.response.authenticatorData);
            r.signature = encode(c.response.signature);
            r.userHandle = c.response.userHandle ? encode(c.response.userHandle) : null;
        }
        return { id: c.id, rawId: encode(c.rawId), type: c.type, response: r,
            authenticatorAttachment: c.authenticatorAttachment || null,
            clientExtensionResults: c.getClientExtensionResults() };
    }
    async function post(kind, step, body) {
        const reply = await fetch('/mail-admin/passkey/' + kind + '/' + step, {
            method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': scope.dataset.csrf },
            body: JSON.stringify(body)
        });
        const data = await reply.json();
        if (!reply.ok || !data.ok) throw new Error(data.error || 'passkey_failed');
        return data;
    }
    async function run(kind) {
        if (busy) return;
        busy = true;
        register.disabled = retry.disabled = true;
        retry.hidden = true;
        result.textContent = '操作を開始しています。';
        try {
            if (kind === 'register') {
                const label = document.getElementById('admin-passkey-label').value.trim();
                if (!label) throw new Error('invalid_label');
                const start = await post('register', 'options', { label });
                const credential = await navigator.credentials.create({ publicKey: options(start.publicKey, 'register') });
                if (!credential) throw new Error('cancelled');
                await post('register', 'finish', { credential: response(credential, 'register') });
                // Registration never grants access; use the existing separate assertion.
                enrollment.hidden = true;
                result.textContent = '登録しました。続けて本人確認を行います。';
            }
            const start = await post('assert', 'options', { label: '' });
            const credential = await navigator.credentials.get({ publicKey: options(start.publicKey, 'assert') });
            if (!credential) throw new Error('cancelled');
            await post('assert', 'finish', { credential: response(credential, 'assert') });
            // Fixed GET only: no return URL or rejected management POST is replayed.
            window.location.assign('/mail-admin/manage');
        } catch (error) {
            // No credential/signature/response/error dump and no automatic retry.
            if (error?.message === 'no_enabled_passkey') {
                enrollment.hidden = false;
                result.textContent = '使用できるPasskeyがありません。未登録の場合は登録名を入力してPasskeyを登録してください。';
            } else {
                result.textContent = '操作を完了できませんでした。認証を再試行するか、再ログイン・登録条件を確認してください。';
            }
            retry.hidden = false;
        } finally { busy = false; register.disabled = retry.disabled = false; }
    }
    if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
        register.disabled = retry.disabled = true;
        result.textContent = 'この環境ではPasskeyを使用できません。';
        return;
    }
    register.addEventListener('click', () => run('register'));
    retry.addEventListener('click', () => run('assert'));
    if (scope.dataset.autoAssert === 'true') run('assert');
}());

(function () {
    'use strict';
    const root = document.getElementById('admin-settings');
    if (!root) return;
    const tabs = [...root.querySelectorAll('[data-admin-tab]')];
    const panels = [...root.querySelectorAll('[data-admin-panel]')];
    const normalize = value => value.normalize('NFKC').toLowerCase();
    root.querySelector('.admin-tabs').setAttribute('role', 'tablist');
    function activate(key, focus = false) {
        if (!panels.some(panel => panel.dataset.adminPanel === key)) return;
        tabs.forEach(tab => {
            const active = tab.dataset.adminTab === key;
            tab.setAttribute('role', 'tab');
            tab.setAttribute('aria-controls', 'panel-' + tab.dataset.adminTab);
            tab.setAttribute('aria-selected', String(active));
            tab.tabIndex = active ? 0 : -1;
            if (active && focus) tab.focus();
        });
        panels.forEach(panel => { panel.hidden = panel.dataset.adminPanel !== key; });
        // Only a four-value UI preference; never store search/input/password/CSRF data.
        try { window.sessionStorage.setItem('mail-admin.selected-tab', key); } catch (_) {}
    }
    tabs.forEach((tab, index) => {
        tab.addEventListener('click', event => { event.preventDefault(); activate(tab.dataset.adminTab); });
        tab.addEventListener('keydown', event => {
            let next = null;
            if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
            if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
            if (event.key === 'Home') next = 0;
            if (event.key === 'End') next = tabs.length - 1;
            if (next !== null) { event.preventDefault(); activate(tabs[next].dataset.adminTab, true); }
        });
    });
    panels.forEach(panel => {
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', 'tab-' + panel.dataset.adminPanel);
        const records = [...panel.querySelectorAll('[data-admin-record]')];
        const filter = panel.querySelector('[data-admin-filter]');
        const size = panel.querySelector('[data-admin-size]');
        const prev = panel.querySelector('[data-admin-prev]');
        const next = panel.querySelector('[data-admin-next]');
        let page = 1;
        function render() {
            const term = normalize(filter.value.trim());
            const matched = records.filter(record => normalize(record.dataset.search).includes(term));
            const count = [20, 50, 100].includes(Number(size.value)) ? Number(size.value) : 20;
            const pages = Math.max(1, Math.ceil(matched.length / count));
            page = Math.max(1, Math.min(page, pages));
            const first = (page - 1) * count;
            const visible = new Set(matched.slice(first, first + count));
            // Hide existing nodes only: tab/filter/page changes never destroy or submit forms.
            records.forEach(record => { record.hidden = !visible.has(record); });
            panel.querySelector('[data-admin-results]').textContent = matched.length
                ? `${first + 1}–${Math.min(first + count, matched.length)} / ${matched.length} 件（取得済み ${records.length} 件）`
                : `0 件（取得済み ${records.length} 件）`;
            panel.querySelector('[data-admin-page]').textContent = `${page} / ${pages}`;
            panel.querySelector('[data-admin-empty]').hidden = matched.length !== 0;
            prev.disabled = page === 1;
            next.disabled = page === pages;
        }
        filter.addEventListener('input', () => { page = 1; render(); });
        size.addEventListener('change', () => { page = 1; render(); });
        prev.addEventListener('click', () => { --page; render(); });
        next.addEventListener('click', () => { ++page; render(); });
        panel.querySelector('[data-admin-controls]').hidden = false;
        panel.querySelector('[data-admin-pager]').hidden = false;
        render();
    });
    const requestedPanel = () => /^#panel-(users|domains|aliases|admins)$/.exec(window.location.hash)?.[1] ?? null;
    window.addEventListener('hashchange', () => { const key = requestedPanel(); if (key) activate(key); });
    let selected = 'users';
    try {
        const saved = window.sessionStorage.getItem('mail-admin.selected-tab');
        if (panels.some(panel => panel.dataset.adminPanel === saved)) selected = saved;
    } catch (_) {}
    activate(requestedPanel() ?? selected);
}());
