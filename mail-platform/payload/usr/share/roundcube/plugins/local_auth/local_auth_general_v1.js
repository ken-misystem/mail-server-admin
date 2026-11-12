(function () {
    'use strict';
    let ownerPolicyState = null;
    function updateOwnerPrerequisiteGuidance() {
        const note = document.getElementById('local-auth-prerequisite-note');
        const supported = Boolean(window.isSecureContext && window.PublicKeyCredential && navigator.credentials);
        const policy = ownerPolicyState;
        const hasProof = !!policy && (policy.recovery_available || supported && policy.passkey_available);
        if (note) note.textContent = rcmail.gettext(!policy ? 'prerequisiteunknown' : policy.passkey_available ? 'prerequisiteready' : policy.recovery_available ? 'prerequisiterecovery' : 'prerequisitenone', 'local_auth');
        const busy = Boolean(registration || removal || recoveryBusy || policyBusy);
        const button = id => document.getElementById(id);
        const recovery = button('local-auth-recovery-replace');
        if (recovery) recovery.disabled = busy || !hasProof;
        const enable = button('local-auth-policy-enable');
        if (enable) enable.disabled = busy || !policy || policy.required || !policy.passkey_available || !policy.recovery_available || !hasProof;
        const disable = button('local-auth-policy-disable');
        if (disable) disable.disabled = busy || !policy || !policy.required || !hasProof;
        const passkey = button('local-auth-proof-passkey');
        if (passkey) passkey.disabled = !policy?.passkey_available || !supported;
        const code = button('local-auth-proof-code'), useCode = button('local-auth-proof-recovery');
        if (code) code.disabled = !policy?.recovery_available;
        if (useCode) useCode.disabled = !policy?.recovery_available;
    }


    function decodeBase64Url(value) {
        const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        return Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
    }

    function encodeBase64Url(value) {
        const bytes = new Uint8Array(value);
        let binary = '';
        bytes.forEach(byte => { binary += String.fromCharCode(byte); });
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function browserCreationOptions(publicKey) {
        publicKey.challenge = decodeBase64Url(publicKey.challenge);
        publicKey.user.id = decodeBase64Url(publicKey.user.id);
        publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map(item => ({
            ...item,
            id: decodeBase64Url(item.id),
        }));
        return publicKey;
    }

    function browserRequestOptions(publicKey) {
        publicKey.challenge = decodeBase64Url(publicKey.challenge);
        publicKey.allowCredentials = (publicKey.allowCredentials || []).map(item => ({
            ...item,
            id: decodeBase64Url(item.id),
        }));
        return publicKey;
    }

    function serializeCredential(credential) {
        return {
            id: credential.id,
            rawId: encodeBase64Url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment || null,
            clientExtensionResults: credential.getClientExtensionResults(),
            response: {
                clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
                attestationObject: encodeBase64Url(credential.response.attestationObject),
                transports: typeof credential.response.getTransports === 'function'
                    ? credential.response.getTransports()
                    : [],
            },
        };
    }

    function serializeAssertion(credential) {
        return {
            id: credential.id,
            rawId: encodeBase64Url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment || null,
            clientExtensionResults: credential.getClientExtensionResults(),
            response: {
                clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
                authenticatorData: encodeBase64Url(credential.response.authenticatorData),
                signature: encodeBase64Url(credential.response.signature),
                userHandle: credential.response.userHandle
                    ? encodeBase64Url(credential.response.userHandle)
                    : null,
            },
        };
    }

    async function post(action, body, failureLabel) {
        const response = await fetch(rcmail.url(action), {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: {
                'Content-Type': 'application/json',
                'X-Roundcube-Request': rcmail.env.request_token,
            },
            body: JSON.stringify(body),
        });
        const result = await response.json();
        if (!response.ok || !result.ok) {
            const message = result.error || rcmail.gettext(failureLabel, 'local_auth');
            const code = typeof result.error_code === 'string' ? result.error_code : 'internal';
            throw new Error(`${message} [${code}]`);
        }
        return result;
    }

    function warnIfNotificationFailed(result) {
        if (result.notification_sent === false) {
            rcmail.display_message(rcmail.gettext('notificationfailed', 'local_auth'), 'warning');
        }
    }

    function renderCredentials(credentials) {
        const container = document.getElementById('local-auth-credentials');
        if (!container) return;
        container.replaceChildren();

        if (!credentials.length) {
            const empty = document.createElement('p');
            empty.textContent = rcmail.gettext('nocredentials', 'local_auth');
            container.appendChild(empty);
            return;
        }

        function credentialRow(item) {
            const row = document.createElement('div');
            row.className = `local-auth-credential ${item.enabled ? 'is-enabled' : 'is-disabled'}`;
            const name = document.createElement('span');
            name.className = 'local-auth-credential-name';
            name.textContent = item.label;
            row.appendChild(name);
            const status = document.createElement('span');
            status.className = 'local-auth-credential-status';
            status.textContent = rcmail.gettext(item.enabled ? 'enabled' : 'disabled', 'local_auth');
            row.appendChild(status);

            if (item.enabled && rcmail.env.local_auth_owner_actions_enabled === true) {
                const button = document.createElement('button');
                button.type = 'button'; button.className = 'button';
                button.textContent = rcmail.gettext('ownerremove', 'local_auth');
                button.disabled = credentials.filter(row => row.enabled).length <= 1;
                if (button.disabled) button.title = rcmail.gettext('lastpasskey', 'local_auth');
                button.addEventListener('click', () => removePasskey(item));
                row.appendChild(button);
            }
            return row;
        }

        const active = credentials.filter(item => item.enabled);
        const inactive = credentials.filter(item => !item.enabled);

        const activeGroup = document.createElement('div');
        activeGroup.className = 'local-auth-credential-group';
        const activeTitle = document.createElement('h3');
        activeTitle.className = 'local-auth-group-title';
        activeTitle.textContent = rcmail.gettext('activepasskeys', 'local_auth');
        activeGroup.appendChild(activeTitle);
        const activeList = document.createElement('div');
        activeList.className = 'local-auth-credential-list';
        active.forEach(item => activeList.appendChild(credentialRow(item)));
        if (!active.length) {
            const empty = document.createElement('p');
            empty.textContent = rcmail.gettext('nocredentials', 'local_auth');
            activeList.appendChild(empty);
        }
        activeGroup.appendChild(activeList);
        container.appendChild(activeGroup);

        if (inactive.length) {
            const history = document.createElement('details');
            history.className = 'local-auth-credential-history';
            const summary = document.createElement('summary');
            summary.textContent = `${rcmail.gettext('inactivepasskeys', 'local_auth')} (${inactive.length})`;
            history.appendChild(summary);
            const inactiveList = document.createElement('div');
            inactiveList.className = 'local-auth-credential-list';
            inactive.forEach(item => inactiveList.appendChild(credentialRow(item)));
            history.appendChild(inactiveList);
            container.appendChild(history);
        }
    }

    async function refreshCredentials() {
        const count = document.getElementById('local-auth-count');
        try {
            const route = 'plugin.local_auth-owner-credentials';
            const result = await uiPost(route, {});
            if (!Array.isArray(result.credentials) || result.credentials.some(item =>
                !item || !Number.isSafeInteger(item.id) || item.id <= 0 || typeof item.label !== 'string' || typeof item.enabled !== 'boolean')) {
                throw new TypeError('metadata');
            }
            const rows = result.credentials;
            updateOwnerPrerequisiteGuidance();
            renderCredentials(rows);
            if (count) count.textContent = rcmail.gettext('credentialcounts', 'local_auth')
                .replace('%total%', String(rows.length))
                .replace('%enabled%', String(rows.filter(item => item.enabled).length))
                .replace('%disabled%', String(rows.filter(item => !item.enabled).length));
        } catch (error) {
            if (count) count.textContent = rcmail.gettext('credentiallistfailed', 'local_auth');
            throw error;
        }
    }

    let registration = null;

    function registrationStatus(state, label, detail = '') {
        const output = document.getElementById('local-auth-result');
        if (!output) return;
        output.dataset.state = state;
        output.setAttribute('role', state === 'failed' || state === 'unverified' ? 'alert' : 'status');
        output.textContent = rcmail.gettext(label, 'local_auth') + (detail ? ` [${detail}]` : '');
        if (typeof output.scrollIntoView === 'function') output.scrollIntoView({ block: 'nearest' });
    }

    function errorCode(error) {
        const known = ['AbortError', 'NotAllowedError', 'InvalidStateError', 'SecurityError',
            'NotSupportedError', 'ConstraintError', 'TypeError', 'NetworkError', 'DataError'];
        if (error && typeof error.safeCode === 'string') return error.safeCode;
        return error && known.includes(error.name) ? error.name : 'browser-error';
    }

    async function uiPost(action, body, signal) {
        const controller = new AbortController();
        const forward = () => controller.abort();
        if (signal) {
            if (signal.aborted) controller.abort();
            else signal.addEventListener('abort', forward, { once: true });
        }
        const timer = setTimeout(() => controller.abort(), 30000);
        try {
            const response = await fetch(rcmail.url(action), {
                method: 'POST', credentials: 'same-origin', cache: 'no-store',
                headers: { 'Content-Type': 'application/json', 'X-Roundcube-Request': rcmail.env.request_token },
                body: JSON.stringify(body), signal: controller.signal,
            });
            const result = await response.json();
            if (!response.ok || !result || result.ok !== true) {
                const error = new Error('server-rejected');
                error.serverRejected = Boolean(result && result.ok === false);
                error.safeCode = result && typeof result.error_code === 'string'
                    && /^[a-z][a-z-]{0,47}$/.test(result.error_code) ? result.error_code : 'server-response';
                throw error;
            }
            return result;
        } finally {
            clearTimeout(timer);
            if (signal) signal.removeEventListener('abort', forward);
        }
    }

    function cancelRegistration() {
        const action = registration || removal;
        if (!action || action.phase === 'finish') return;
        action.cancelled = true; action.controller.abort();
        registrationStatus('cancelling', 'registrationcancelling');
    }

    async function registerPasskey() {
        if (registration || removal || recoveryBusy || policyBusy) return;
        const input = document.getElementById('local-auth-label');
        const cancel = document.getElementById('local-auth-cancel');
        const label = input.value.trim();
        if (!label) { registrationStatus('failed', 'labelrequired', 'input'); return; }
        registration = { phase: 'options', cancelled: false, controller: new AbortController() };
        if (cancel) { cancel.hidden = false; cancel.disabled = false; }
        try {
            registrationStatus('running', 'registrationstarting');
            let start;
            try { start = await uiPost('plugin.local_auth-register-options', {}, registration.controller.signal); }
            catch (error) {
                if (!(error && error.serverRejected && error.safeCode === 'authentication' && rcmail.env.local_auth_management_enabled === true)) throw error;
                registration.phase = 'authorize';
                registrationStatus('running', 'actionverify');
                await verifyPasskey(registration.controller.signal);
                if (registration.controller.signal.aborted) throw new DOMException('', 'AbortError');
                registration.phase = 'options';
                start = await uiPost('plugin.local_auth-register-options', {}, registration.controller.signal);
            }
            if (registration.controller.signal.aborted) throw new DOMException('', 'AbortError');
            registration.phase = 'create';
            registrationStatus('running', 'registrationwaiting');
            const credential = await navigator.credentials.create({
                publicKey: browserCreationOptions(start.publicKey), signal: registration.controller.signal,
            });
            // Abort may race with successful authenticator completion. Never
            // submit a late returned credential after explicit cancellation.
            if (registration.controller.signal.aborted) throw new DOMException('', 'AbortError');
            if (!credential) throw new DOMException('', 'NotAllowedError');
            const serialized = serializeCredential(credential);
            registration.phase = 'finish';
            if (cancel) cancel.disabled = true;
            registrationStatus('running', 'registrationsaving');
            const result = await uiPost('plugin.local_auth-register-finish', {
                ceremony_id: start.ceremony_id, label, credential: serialized,
            });
            registration.phase = 'complete';
            input.value = '';
            registrationStatus('success', 'registrationsucceeded');
            warnIfNotificationFailed(result);
            refreshOwnerPolicy().catch(() => {});
            try { await refreshCredentials(); }
            catch (error) { registrationStatus('success', 'registrationsuccesslistfailed', errorCode(error)); }
        } catch (error) {
            const code = errorCode(error);
            if (registration.phase === 'complete') {
                registrationStatus('success', 'registrationsuccessdisplayfailed', code);
            } else if (registration.phase === 'finish' && (!(error && error.serverRejected) || code === 'registration-unverified')) {
                registrationStatus('unverified', 'registrationunverified', `finish:${code}`);
            } else if (code === 'proof-unverified') {
                registrationStatus('unverified', 'ownerproofunverified', code);
            } else if (registration.cancelled) {
                registrationStatus('cancelled', 'registrationcancelled', code);
            } else if ((registration.phase === 'create' || registration.phase === 'authorize') && (code === 'NotAllowedError' || code === 'AbortError')) {
                registrationStatus('cancelled', 'registrationcancelledortimeout', code);
            } else {
                registrationStatus('failed', 'registrationfailedsafe', `${registration.phase}:${code}`);
            }
        } finally {
            registration = null;
            if (cancel) { cancel.hidden = true; cancel.disabled = true; }
        }
    }

    // On-demand proof only: no independent verification field or secret storage.
    function selectOwnerProof(signal) {
        if (ownerPolicyState && ownerPolicyState.passkey_available) return Promise.resolve({kind:'passkey'});
        if (!ownerPolicyState || !ownerPolicyState.recovery_available) {
            const error = new Error('factor-unavailable'); error.safeCode='factor-unavailable'; return Promise.reject(error);
        }
        updateOwnerPrerequisiteGuidance();
        const dialog = document.getElementById('local-auth-proof-dialog');
        const input = document.getElementById('local-auth-proof-code');
        if (!dialog || !input || typeof dialog.showModal !== 'function') {
            // Older browsers retain the existing Passkey approval path.
            return Promise.resolve({ kind: 'passkey' });
        }
        return new Promise((resolve, reject) => {
            let settled = false;
            const bindings = [];
            function on(target, event, fn) { target.addEventListener(event, fn); bindings.push([target, event, fn]); }
            function finish(kind) {
                if (settled) return;
                settled = true;
                const code = kind === 'recovery' ? input.value.trim() : '';
                input.value = '';
                bindings.forEach(([target, event, fn]) => target.removeEventListener(event, fn));
                if (dialog.open) dialog.close();
                if (kind === 'cancel') reject(new DOMException('', 'AbortError'));
                else resolve({ kind, code });
            }
            on(document.getElementById('local-auth-proof-passkey'), 'click', () => finish('passkey'));
            on(document.getElementById('local-auth-proof-recovery'), 'click', () => finish('recovery'));
            on(document.getElementById('local-auth-proof-cancel'), 'click', () => finish('cancel'));
            on(dialog, 'cancel', event => { event.preventDefault(); finish('cancel'); });
            on(dialog, 'close', () => finish('cancel'));
            on(window, 'pagehide', () => finish('cancel'));
            if (signal) on(signal, 'abort', () => finish('cancel'));
            input.value = '';
            if (signal && signal.aborted) { finish('cancel'); return; }
            try { dialog.showModal(); }
            catch (error) { finish('cancel'); }
        });
    }

    async function verifyPasskey(signal) {
        const shared = await uiPost('plugin.local_auth-owner-verification-status', {}, signal);
        if (shared.authentication_required === false) return;
        await refreshOwnerPolicy();
        const proof = await selectOwnerProof(signal);
        if (signal && signal.aborted) throw new DOMException('', 'AbortError');
        if (proof.kind === 'passkey') return verifyExistingPasskey(signal);
        try {
            await uiPost('plugin.local_auth-owner-recovery-verify', { code: proof.code }, signal);
            if (signal && signal.aborted) throw new DOMException('', 'AbortError');
        } catch (error) {
            // A lost response can mean a one-use code was consumed. Never
            // classify it as cancellation or automatically submit it again.
            if (!(error && error.serverRejected)) {
                const unknown = new Error('proof-outcome-unavailable');
                unknown.safeCode = 'proof-unverified';
                throw unknown;
            }
            throw error;
        } finally { proof.code = ''; }
    }

    async function verifyExistingPasskey(signal) {
        const start = await uiPost('plugin.local_auth-assert-options', {}, signal);
        if (start.authentication_required === false) return;
        if (signal && signal.aborted) throw new DOMException('', 'AbortError');
        const credential = await navigator.credentials.get({ publicKey: browserRequestOptions(start.publicKey), signal });
        if (signal && signal.aborted) throw new DOMException('', 'AbortError');
        if (!credential) throw new DOMException('', 'NotAllowedError');
        await uiPost('plugin.local_auth-assert-finish', { ceremony_id: start.ceremony_id, credential: serializeAssertion(credential) }, signal);
    }


    let removal = null;
    let recoveryBusy = false;
    async function removePasskey(item) {
        if (registration || removal || recoveryBusy || policyBusy) return;
        if (!window.confirm(rcmail.gettext('ownerremoveconfirm', 'local_auth'))) return;
        removal = { phase: 'options', cancelled: false, controller: new AbortController() };
        const cancel = document.getElementById('local-auth-cancel');
        if (cancel) { cancel.hidden = false; cancel.disabled = false; }
        try {
            registrationStatus('running', 'ownerremoveauth');
            await verifyExistingPasskey(removal.controller.signal);
            const start = await uiPost('plugin.local_auth-owner-remove-options', { credential_id: item.id }, removal.controller.signal);
            if (removal.controller.signal.aborted) throw new DOMException('', 'AbortError');
            removal.phase = 'verify';
            if (start.authentication_required !== false) throw new TypeError('verification_contract');
            const serialized = null;
            removal.phase = 'finish';
            if (cancel) cancel.disabled = true;
            registrationStatus('running', 'ownerremovesaving');
            const result = await uiPost('plugin.local_auth-owner-remove-finish', { ceremony_id: start.ceremony_id, credential: serialized });
            removal.phase = 'complete';
            registrationStatus('success', result.session_warning ? 'ownerremovesessionwarning' : 'ownerremoved');
            warnIfNotificationFailed(result);
            refreshOwnerPolicy().catch(() => {});
            try { await refreshCredentials(); }
            catch (error) { registrationStatus('success', 'ownerremovelistfailed', errorCode(error)); }
        } catch (error) {
            const code = errorCode(error);
            if (removal.phase === 'complete') registrationStatus('success', 'ownerremovesessionwarning', code);
            else if (removal.phase === 'finish' && (!(error && error.serverRejected) || code === 'removal-unverified')) registrationStatus('unverified', 'ownerremoveunverified', code);
            else if (removal.cancelled || (removal.phase === 'verify' && code === 'NotAllowedError')) registrationStatus('cancelled', 'ownerremovecancelled', code);
            else registrationStatus('failed', code === 'last-factor' ? 'lastpasskey' : 'ownerremovefailed', `${removal.phase}:${code}`);
        } finally {
            removal = null;
            if (cancel) { cancel.hidden = true; cancel.disabled = true; }
        }
    }

    async function replaceRecoveryCodes() {
        if (registration || removal || recoveryBusy || policyBusy) return;
        if (!window.confirm(rcmail.gettext('confirmrecoveryreplace', 'local_auth'))) return;
        const output = document.getElementById('local-auth-recovery-codes');
        if (!output) return;
        recoveryBusy = true;
        output.textContent = ''; output.hidden = true;
        let phase = 'verify';
        try {
            registrationStatus('running', 'actionverify');
            await verifyPasskey();
            phase = 'finish';
            const result = await uiPost('plugin.local_auth-recovery-replace', {});
            if (!Array.isArray(result.recovery_codes) || result.recovery_codes.some(v => typeof v !== 'string')) throw new TypeError('response');
            phase = 'complete';
            output.textContent = result.recovery_codes.join('\n'); output.hidden = false;
            registrationStatus('success', 'recoveryreplacedsucceeded');
            warnIfNotificationFailed(result);
            refreshOwnerPolicy().catch(() => {});
        } catch (error) {
            const code = errorCode(error);
            if (phase === 'complete') registrationStatus('success', 'recoveryreplacedsucceeded', code);
            else if (phase === 'finish' && (!(error && error.serverRejected) || code === 'recovery-unverified')) registrationStatus('unverified', 'recoveryunverified', code);
            else if (code === 'proof-unverified') registrationStatus('unverified', 'ownerproofunverified', code);
            else if (phase === 'verify' && (code === 'NotAllowedError' || code === 'AbortError')) registrationStatus('cancelled', 'registrationcancelledortimeout', code);
            else registrationStatus('failed', 'managementfailed', code);
        } finally { recoveryBusy = false; }
    }

    let policyBusy = false;

    async function refreshOwnerPolicy() {
        const output = document.getElementById('local-auth-policy-state');
        const enable = document.getElementById('local-auth-policy-enable');
        const disable = document.getElementById('local-auth-policy-disable');
        if (!output || !enable || !disable) return;
        enable.disabled = disable.disabled = true;
        try {
            const result = await uiPost('plugin.local_auth-owner-policy', {});
            const policy = result.policy;
            if (!policy || ['required','configured','passkey_available','recovery_available'].some(k => typeof policy[k] !== 'boolean')) throw new TypeError('policy');
            ownerPolicyState = policy;
            output.textContent = rcmail.gettext(policy.required ? 'ownerpolicyrequired' : 'ownerpolicyoptional', 'local_auth');
            enable.disabled = policy.required || !policy.passkey_available || !policy.recovery_available;
            disable.disabled = !policy.required;
            updateOwnerPrerequisiteGuidance();
        } catch (error) {
            ownerPolicyState = null; updateOwnerPrerequisiteGuidance();
            output.textContent = rcmail.gettext('ownerpolicyunknown', 'local_auth');
            throw error;
        }
    }

    async function saveOwnerPolicy(required) {
        if (registration || removal || recoveryBusy || policyBusy) return;
        if (!window.confirm(rcmail.gettext(required ? 'ownerpolicyenableconfirm' : 'ownerpolicydisableconfirm', 'local_auth'))) return;
        policyBusy = true;
        let phase = 'verify';
        try {
            registrationStatus('running', 'actionverify');
            await verifyPasskey();
            phase = 'finish';
            const result = await uiPost('plugin.local_auth-owner-policy-save', { required });
            phase = 'complete';
            registrationStatus('success', result.session_warning ? 'ownerpolicysessionwarning' : 'ownerpolicysaved');
            warnIfNotificationFailed(result);
            try { await refreshOwnerPolicy(); }
            catch (error) { registrationStatus('success', 'ownerpolicysavedrefreshfailed', errorCode(error)); }
        } catch (error) {
            const code = errorCode(error);
            if (phase === 'complete') registrationStatus('success', 'ownerpolicysavedrefreshfailed', code);
            else if (code === 'proof-unverified') registrationStatus('unverified', 'ownerproofunverified', code);
            else if (phase === 'finish' && (!(error && error.serverRejected) || code === 'policy-unverified')) registrationStatus('unverified', 'ownerpolicyunverified', code);
            else if (phase === 'verify' && ['AbortError','NotAllowedError'].includes(code)) registrationStatus('cancelled', 'ownerpolicycancelled', code);
            else registrationStatus('failed', code === 'last-factor' ? 'ownerpolicyfactorsrequired' : 'managementfailed', code);
        } finally { policyBusy = false; }
    }

    function bindButton(id, action) {
        const button = document.getElementById(id);
        if (!button) return;
        button.addEventListener('click', function () {
            button.disabled = true;
            action()
                .catch(error => rcmail.display_message(error.message, 'error'))
                .finally(() => { button.disabled = false; updateOwnerPrerequisiteGuidance(); });
        });
    }

    rcmail.addEventListener('init', function () {
        updateOwnerPrerequisiteGuidance();
        const managementEnabled = rcmail.env.local_auth_management_enabled === true;
        const supported = Boolean(window.PublicKeyCredential && navigator.credentials);
        const register = document.getElementById('local-auth-register');
        if (!supported) {
            if (register) register.disabled = true;
        } else {
            bindButton('local-auth-register', registerPasskey);
        }
        const cancel = document.getElementById('local-auth-cancel');
        if (cancel) cancel.addEventListener('click', cancelRegistration);
        bindButton('local-auth-refresh', async function () {
            try { await refreshCredentials(); }
            catch (error) { registrationStatus('failed', 'credentiallistfailed', errorCode(error)); }
        });
        if (managementEnabled) {
            bindButton('local-auth-recovery-replace', replaceRecoveryCodes);
            bindButton('local-auth-policy-enable', () => saveOwnerPolicy(true));
            bindButton('local-auth-policy-disable', () => saveOwnerPolicy(false));
            refreshOwnerPolicy().catch(error => registrationStatus('failed', 'ownerpolicyunknown', errorCode(error)));

        }
        if (rcmail.env.local_auth_owner_list_enabled === true) {
            refreshCredentials().catch(error => registrationStatus('failed', 'credentiallistfailed', errorCode(error)));
        }
        if (!supported) registrationStatus('failed', 'passkeyunsupported');
        if (managementEnabled && typeof window.addEventListener === 'function') {
            window.addEventListener('pagehide', function () {
                const output = document.getElementById('local-auth-recovery-codes');
                if (output) {
                    output.textContent = '';
                    output.hidden = true;
                }
            });
        }
    });
}());
