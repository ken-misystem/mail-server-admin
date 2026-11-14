/* SPDX-License-Identifier: MIT */
'use strict';
window.addEventListener('load', () => {
    if (typeof rcmail === 'undefined' || !document.getElementById('ms-settings')) return;
    const byId = id => document.getElementById(id);
    const form = byId('ms-form'), message = byId('ms-message');
    let snapshot = null, busy = false, uncertain = false, pendingPayload = null, inspected = null;
    const editor = new MiSieveEditor(byId('ms-document-editor'));
    for (const button of document.querySelectorAll('#ms-settings button')) button.classList.add('button');
    for (const input of document.querySelectorAll('#ms-settings input:not([type=checkbox]), #ms-settings textarea, #ms-settings select')) input.classList.add('form-control');
    const errors = {
        settings_conflict: '他の画面で設定が更新されています。最新の設定を読み込んでから編集してください。',
        settings_busy: '別の設定操作が進行中です。',
        save_unverified: '保存の結果を確認できません。最新の設定を読み込んで確認してください。',
        result_unverified: '保存後の読戻しに失敗しました。最新の設定を読み込んで確認してください。',
        script_limit: '保存世代の上限に達しました。管理者へ連絡してください。',
        managed_script_changed: '生成済みSieveが外部で変更されています。管理者へ確認してください。',
        base_script_changed: '既存Sieveの保存コピーが変更されています。管理者へ確認してください。',
        script_referenced: '有効なルール、別のSieveから参照中のルール、保護された保存世代は削除・名前変更できません。',
        unavailable: '設定を取得・保存できません。時間をおいて管理者へ確認してください。'
    };
    function controls() {
        for (const element of form.elements) element.disabled = busy || !snapshot || uncertain || pendingPayload !== null;
        byId('ms-refresh').disabled = busy || pendingPayload !== null;
        byId('ms-confirm-accept').disabled = busy;
        byId('ms-confirm-cancel').disabled = busy;
    }
    async function request(payload) {
        if (busy) return;
        busy = true; controls();
        const timeout = new AbortController(), timer = setTimeout(() => timeout.abort(), 30000);
        try {
            const response = await fetch(rcmail.url('plugin.mail_settings-rpc'), {
                method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: timeout.signal,
                headers: {'Content-Type': 'application/json', 'X-Roundcube-Request': rcmail.env.request_token},
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (!response.ok || data.ok !== true) throw new Error(data.error_code || 'unavailable');
            snapshot = data.snapshot; uncertain = false; render(data.versions);
            inspected = data.inspected || null;
            if (inspected) {
                editor.load(inspected.document, snapshot.extensions); selectTab(tabs.findIndex(tab => tab.id === 'ms-tab-document'));
                byId('ms-set-current').textContent = '選択中 ' + inspected.name;
            }
            message.textContent = payload.operation === 'load' ? '最新の設定を表示しています。' : '設定を保存し、読戻しを確認しました。';
        } catch (error) {
            uncertain = true;
            message.textContent = errors[error.message] || '通信結果を確認できません。最新の設定を読み込んでください。';
        } finally { clearTimeout(timer); busy = false; controls(); }
    }
    const tabs = Array.from(document.querySelectorAll('.ms-tabs [role="tab"]'));
    function selectTab(index) {
        tabs.forEach((tab, number) => {
            const selected = index === number;
            tab.setAttribute('aria-selected', String(selected)); tab.tabIndex = selected ? 0 : -1;
            byId(tab.getAttribute('aria-controls')).hidden = !selected;
        });
    }
    tabs.forEach((tab, index) => {
        tab.addEventListener('click', () => selectTab(index));
        tab.addEventListener('keydown', event => {
            const shifts = {ArrowRight: 1, ArrowLeft: -1};
            let next;
            if (event.key === 'Home') next = 0;
            else if (event.key === 'End') next = tabs.length - 1;
            else if (event.key in shifts) next = (index + shifts[event.key] + tabs.length) % tabs.length;
            else return;
            event.preventDefault(); selectTab(next); tabs[next].focus();
        });
    });
    function choice(label, options, value) {
        const wrapper = document.createElement('label'); wrapper.append(document.createTextNode(label));
        const select = document.createElement('select');
        for (const [key, text] of options) { const option = document.createElement('option'); option.value = key; option.textContent = text; select.append(option); }
        select.value = value; wrapper.append(select); return [wrapper, select];
    }
    function ruleElement(rule) {
        const row = document.createElement('div'); row.className = 'ms-rule';
        const [fieldLabel, field] = choice('対象', [['subject', '件名'], ['from', '差出人'], ['to', '宛先']], rule.field);
        const [matchLabel, match] = choice('条件', [['contains', '含む'], ['is', '一致する']], rule.match);
        const valueLabel = document.createElement('label'); valueLabel.textContent = '比較する文字列';
        const value = document.createElement('input'); value.type = 'text'; value.maxLength = 512; value.value = rule.value; valueLabel.append(value);
        const [actionLabel, action] = choice('処理', [['fileinto', 'フォルダーへ保存'], ['keep', '受信箱へ保存'], ['discard', '破棄']], rule.action);
        const targetLabel = document.createElement('label'); targetLabel.textContent = 'フォルダー名';
        const target = document.createElement('input'); target.type = 'text'; target.maxLength = 255; target.value = rule.target; targetLabel.append(target);
        const stopLabel = document.createElement('label'), stop = document.createElement('input'); stop.type = 'checkbox'; stop.checked = rule.stop;
        stopLabel.append(stop, document.createTextNode('一致したら以降の処理を終了する'));
        const actions = document.createElement('div'); actions.className = 'ms-rule-actions';
        for (const [text, handler] of [
            ['上へ', () => { if (row.previousElementSibling) row.parentNode.insertBefore(row, row.previousElementSibling); }],
            ['下へ', () => { if (row.nextElementSibling) row.parentNode.insertBefore(row.nextElementSibling, row); }],
            ['削除', () => row.remove()]
        ]) { const button = document.createElement('button'); button.type = 'button'; button.textContent = text; button.addEventListener('click', handler); actions.append(button); }
        row.append(fieldLabel, matchLabel, valueLabel, actionLabel, targetLabel, stopLabel, actions);
        row.readRule = () => ({field: field.value, match: match.value, value: value.value, action: action.value,
            target: action.value === 'fileinto' ? target.value : '', stop: stop.checked});
        return row;
    }
    function render(versions) {
        const model = snapshot.model;
        byId('ms-forward-enabled').checked = model.forward.enabled;
        byId('ms-forward-keep').checked = model.forward.keep;
        byId('ms-forward-targets').value = model.forward.targets.join('\n');
        byId('ms-vacation-enabled').checked = model.vacation.enabled;
        byId('ms-vacation-days').value = model.vacation.days;
        byId('ms-vacation-subject').value = model.vacation.subject;
        byId('ms-vacation-body').value = model.vacation.body;
        byId('ms-base-source').value = snapshot.base_source; byId('ms-base-source').readOnly = true; byId('ms-base-edit').checked = false;
        byId('ms-rule-list').replaceChildren(...model.rules.map(ruleElement));
        byId('ms-version').replaceChildren();
        versions.forEach((version, index) => { const option = document.createElement('option'); option.value = version;
            option.textContent = '保存世代 ' + (index + 1) + ' · ' + version.slice(12, 24) + (version === snapshot.active ? '（現在）' : ''); byId('ms-version').append(option); });
        byId('ms-document-target').value = 'source';
        editor.load(snapshot.document, snapshot.extensions);
        byId('ms-set-list').replaceChildren(...snapshot.script_names.map(name => {
            const option = document.createElement('option'); option.value = name;
            option.textContent = name + (name === snapshot.active ? '（有効）' : ''); return option;
        }));
        byId('ms-set-current').textContent = '有効Sieve全体を表示中';
    }
    byId('ms-rule-add').addEventListener('click', () => {
        if (byId('ms-rule-list').children.length >= 32) { message.textContent = 'ルールは最大32件です。'; return; }
        byId('ms-rule-list').append(ruleElement({field: 'subject', match: 'contains', value: '', action: 'fileinto', target: 'Junk', stop: true}));
    });
    byId('ms-base-edit').addEventListener('change', () => { byId('ms-base-source').readOnly = !byId('ms-base-edit').checked; });
    form.addEventListener('submit', event => {
        event.preventDefault(); if (!snapshot || busy || uncertain) return;
        if (!byId('ms-document').hidden) {
            if (inspected && inspected.name !== snapshot.active) {
                message.textContent = '別のルールを編集中です。新しい名前で保存するか、選択ルールを有効化してください。'; return;
            }
            confirmChange({operation: byId('ms-document-target').value === 'source' ? 'save_document' : 'save_base_document',
                revision: snapshot.revision, document: editor.value()}, '表示中の詳細ルールを保存します。既存の有効ルールは構文検証と競合確認が完了してから切り替わります。');
            return;
        }
        const model = structuredClone(snapshot.model);
        model.forward = {enabled: byId('ms-forward-enabled').checked, keep: byId('ms-forward-keep').checked,
            targets: byId('ms-forward-targets').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean)};
        model.vacation = {enabled: byId('ms-vacation-enabled').checked, days: Number(byId('ms-vacation-days').value),
            subject: byId('ms-vacation-subject').value, body: byId('ms-vacation-body').value};
        model.rules = Array.from(byId('ms-rule-list').children, row => row.readRule());
        const payload = {operation: 'save', revision: snapshot.revision, model};
        if (byId('ms-base-edit').checked) payload.base_source = byId('ms-base-source').value;
        confirmChange(payload, '保存した設定は今後の受信から適用されます。内容を確認して実行してください。');
    });
    byId('ms-restore').addEventListener('click', () => {
        if (snapshot && !busy && !uncertain && byId('ms-version').value) {
            confirmChange({operation: 'restore', revision: snapshot.revision, version: byId('ms-version').value}, '選択した世代の設定へ戻します。内容を確認して実行してください。');
        }
    });
    function confirmChange(payload, text) {
        pendingPayload = payload; byId('ms-confirm-text').textContent = text;
        byId('ms-confirm').hidden = false; controls(); byId('ms-confirm-accept').focus();
    }
    byId('ms-confirm-accept').addEventListener('click', () => {
        if (!pendingPayload || busy) return;
        const payload = pendingPayload; pendingPayload = null; byId('ms-confirm').hidden = true; request(payload);
    });
    byId('ms-confirm-cancel').addEventListener('click', () => {
        pendingPayload = null; byId('ms-confirm').hidden = true; controls(); byId('ms-save').focus();
    });
    byId('ms-refresh').addEventListener('click', () => request({operation: 'load'}));
    byId('ms-document-target').addEventListener('change', () => {
        inspected = null; byId('ms-set-current').textContent = '有効Sieveの編集範囲を表示中';
        editor.load(byId('ms-document-target').value === 'source' ? snapshot.document : snapshot.base_document, snapshot.extensions);
    });
    byId('ms-document-import').addEventListener('change', async event => {
        const file = event.target.files[0];
        if (!file || file.size > 65536 || busy || uncertain) return;
        busy = true; controls();
        const timeout = new AbortController();
        const timer = setTimeout(() => timeout.abort(), 30000);
        try {
            const response = await fetch(rcmail.url('plugin.mail_settings-rpc'), {
                method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: timeout.signal,
                headers: {'Content-Type': 'application/json', 'X-Roundcube-Request': rcmail.env.request_token},
                body: JSON.stringify({operation: 'parse_source', source: await file.text()})
            });
            const data = await response.json();
            if (!response.ok || data.ok !== true) throw new Error('invalid_script');
            editor.load(data.document, snapshot.extensions);
            message.textContent = 'ファイルを編集画面へ読み込みました。保存すると今後の受信から適用されます。';
        } catch (error) { message.textContent = 'ファイルを読み込めません。UTF-8のSieveと構文を確認してください。'; }
        finally { clearTimeout(timer); busy = false; event.target.value = ''; controls(); }
    });
    byId('ms-document-export').addEventListener('click', () => {
        const source = inspected ? inspected.source : (byId('ms-document-target').value === 'source' ? snapshot.source : snapshot.base_source);
        const url = URL.createObjectURL(new Blob([source], {type: 'application/sieve;charset=utf-8'}));
        const link = document.createElement('a'); link.href = url; link.download = 'mail-rules.sieve'; link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    byId('ms-set-open').addEventListener('click', () => request({operation: 'inspect_set', script_name: byId('ms-set-list').value}));
    byId('ms-set-copy').addEventListener('click', () => {
        if (!snapshot || busy || uncertain) return;
        confirmChange({operation: 'copy_set', revision: snapshot.revision, new_name: byId('ms-set-name').value,
            document: editor.value()}, '編集画面の内容を新しい名前で保存します。有効ルールの切替えは有効化ボタンで行います。');
    });
    for (const [id, operation, text] of [
        ['ms-set-activate', 'activate_set', '選択したルールを有効化します。'],
        ['ms-set-delete', 'delete_set', '選択した未使用ルールを削除します。保存世代は保持します。'],
        ['ms-set-rename', 'rename_set', '選択したルールを新しい名前へ移します。参照中のルールは移せません。']
    ]) byId(id).addEventListener('click', () => {
        if (!inspected || busy || uncertain) { message.textContent = '先に対象のルールを開いてください。'; return; }
        confirmChange({operation, revision: snapshot.revision, script_name: inspected.name,
            script_sha256: inspected.sha256, new_name: byId('ms-set-name').value}, text);
    });
    controls(); request({operation: 'load'});
});
