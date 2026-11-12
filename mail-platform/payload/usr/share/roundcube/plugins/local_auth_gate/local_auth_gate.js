(function () {
    'use strict';

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

    function browserRequestOptions(publicKey) {
        publicKey.challenge = decodeBase64Url(publicKey.challenge);
        publicKey.allowCredentials = (publicKey.allowCredentials || []).map(item => ({
            ...item,
            id: decodeBase64Url(item.id),
        }));
        return publicKey;
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

    function serializeRegistration(credential) {
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

    async function post(action, body) {
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
            const message = result.error || rcmail.gettext('verificationfailed', 'local_auth_gate');
            const code = typeof result.error_code === 'string' ? result.error_code : 'internal';
            throw new Error(`${message} [${code}]`);
        }
        return result;
    }

    async function verifyPasskey() {
        const start = await post('plugin.local_auth_gate-assert-options', {});
        const credential = await navigator.credentials.get({
            publicKey: browserRequestOptions(start.publicKey),
        });
        if (!credential) throw new Error(rcmail.gettext('verificationfailed', 'local_auth_gate'));
        const result = await post('plugin.local_auth_gate-assert-finish', {
            ceremony_id: start.ceremony_id,
            credential: serializeAssertion(credential),
        });
        window.location.replace(result.redirect);
    }

    async function verifyRecoveryCode() {
        const input = document.getElementById('local-auth-gate-recovery-code');
        const code = input.value.trim();
        if (!code) throw new Error(rcmail.gettext('recoveryrequired', 'local_auth_gate'));
        try {
            const result = await post('plugin.local_auth_gate-recovery-finish', {
                recovery_code: code,
            });
            input.value = '';
            window.location.replace(result.redirect);
        } catch (error) {
            input.value = '';
            throw error;
        }
    }

    async function claimEmergencyToken() {
        const input = document.getElementById('local-auth-gate-emergency-token');
        const token = input.value;
        if (!token) throw new Error(rcmail.gettext('emergencyrequired', 'local_auth_gate'));
        try {
            const result = await post('plugin.local_auth_gate-emergency-claim', {
                emergency_token: token,
            });
            input.value = '';
            window.location.replace(result.redirect);
        } catch (error) {
            input.value = '';
            throw error;
        }
    }

    async function enrollReplacement() {
        const labelInput = document.getElementById('local-auth-emergency-label');
        const label = labelInput.value.trim();
        if (!label) throw new Error(rcmail.gettext('emergencylabelrequired', 'local_auth_gate'));

        const start = await post('plugin.local_auth_gate-emergency-options', {});
        const credential = await navigator.credentials.create({
            publicKey: browserCreationOptions(start.publicKey),
        });
        if (!credential) throw new Error(rcmail.gettext('verificationfailed', 'local_auth_gate'));

        await post('plugin.local_auth_gate-emergency-finish', {
            ceremony_id: start.ceremony_id,
            label,
            credential: serializeRegistration(credential),
        });
        labelInput.value = '';
        window.location.replace(rcmail.url('logout'));
    }

    function bind(id, action) {
        const button = document.getElementById(id);
        if (!button) return;
        button.addEventListener('click', function () {
            button.disabled = true;
            action()
                .catch(error => rcmail.display_message(error.message, 'error'))
                .finally(() => { button.disabled = false; });
        });
    }

    rcmail.addEventListener('init', function () {
        const ready = Boolean(rcmail.env.local_auth_gate_ready);
        const passkeySupported = Boolean(window.PublicKeyCredential && navigator.credentials);
        const passkeyButton = document.getElementById('local-auth-gate-verify');
        const recoveryButton = document.getElementById('local-auth-gate-recovery');
        const emergencyClaimButton = document.getElementById('local-auth-gate-emergency-claim');
        const emergencyEnrollButton = document.getElementById('local-auth-emergency-enroll');

        if (passkeyButton) {
            passkeyButton.disabled = !ready || !rcmail.env.local_auth_gate_passkey || !passkeySupported;
        }
        if (recoveryButton) {
            recoveryButton.disabled = !ready || !rcmail.env.local_auth_gate_recovery;
        }
        if (passkeyButton && !passkeyButton.disabled) bind('local-auth-gate-verify', verifyPasskey);
        if (recoveryButton && !recoveryButton.disabled) bind('local-auth-gate-recovery', verifyRecoveryCode);
        if (emergencyClaimButton) {
            emergencyClaimButton.disabled = !ready || !rcmail.env.local_auth_gate_emergency;
        }
        if (emergencyClaimButton && !emergencyClaimButton.disabled) {
            bind('local-auth-gate-emergency-claim', claimEmergencyToken);
        }
        if (emergencyEnrollButton) {
            emergencyEnrollButton.disabled = !passkeySupported
                || rcmail.env.local_auth_emergency_ready !== true;
        }
        if (emergencyEnrollButton && !emergencyEnrollButton.disabled) {
            bind('local-auth-emergency-enroll', enrollReplacement);
        }
    });
}());
