(function () {
    'use strict';
    let busy = false;
    let preferencesLoaded = false;
    const messages = {alias_limit: '管理者が設定した上限に達しているか、作成が許可されていません。',
        alias_unavailable: 'その受信名は使用できません。', invalid_alias: '受信名を確認してください。',
        result_unverified: '結果を確認できません。再送せず一覧を更新してください。'};
    async function post(command) {
        const response = await fetch(rcmail.url('plugin.mail_aliases-rpc'), {method: 'POST', credentials: 'same-origin',
            cache: 'no-store', headers: {'Content-Type': 'application/json', 'X-Roundcube-Request': rcmail.env.request_token},
            body: JSON.stringify(command)});
        const result = await response.json();
        if (!response.ok || result.ok !== true) {
            const error = new Error(messages[result.error_code] || '操作できません。結果が不明な場合は再送しないでください。');
            error.aliasUiSafe = true; throw error;
        }
        return result;
    }
    function button(label, action) {
        const node = document.createElement('button'); node.type = 'button'; node.className = 'button'; node.textContent = label;
        node.addEventListener('click', action); return node;
    }
    async function refresh() {
        const usage = document.getElementById('mail-aliases-usage');
        usage.textContent = '登録エイリアス数：取得中…';
        const result = await post({kind: 'list'}).catch(error => {
            usage.textContent = '登録エイリアス数：取得できません。'; throw error;
        }), list = document.getElementById('mail-aliases-list');
        if (!result.usage || !Number.isSafeInteger(result.usage.count) || result.usage.count < 0
            || !Number.isSafeInteger(result.usage.limit) || result.usage.limit < 0 || result.usage.limit > 1000
            || !Array.isArray(result.aliases)) { usage.textContent = '登録エイリアス数：取得できません。'; throw new Error('usage unavailable'); }
        if (!result.preferences || typeof result.preferences.ignore_dots !== 'boolean'
            || typeof result.preferences.allow_plus !== 'boolean') { throw new Error('preferences unavailable'); }
        document.getElementById('mail-aliases-ignore-dots').checked = result.preferences.ignore_dots;
        document.getElementById('mail-aliases-allow-plus').checked = result.preferences.allow_plus;
        preferencesLoaded = true;
        usage.textContent = '登録エイリアス数：' + result.usage.count + ' / ' + result.usage.limit + ' 件（停止中を含む）';
        if (!busy) document.getElementById('mail-aliases-preferences').querySelectorAll('button,input').forEach(node => {node.disabled = false;});
        list.replaceChildren();
        for (const alias of result.aliases) {
            const row = document.createElement('div'), name = document.createElement('span'); row.className = 'mail-alias-row';
            name.className = 'mail-alias-address'; name.textContent = alias.source + (alias.active ? '（有効）' : '（停止）'); row.append(name);
            row.append(button(alias.active ? '停止' : '有効にする', () => operate({kind: 'state', id: alias.id, enabled: !alias.active})));
            row.append(button('削除', () => {if (window.confirm(alias.source + ' の受信経路を削除します。保存済みメールは削除しません。')) operate({kind: 'remove', id: alias.id, confirm: 'remove'});}));
            list.append(row);
        }
        if (!result.aliases.length) {const empty = document.createElement('p'); empty.textContent = '自分で登録した受信エイリアスはありません。'; list.append(empty);}
    }
    async function operate(command) {
        if (busy) return;
        busy = true; const panel = document.getElementById('mail-aliases-panel'), status = document.getElementById('mail-aliases-message');
        panel.querySelectorAll('button,input').forEach(node => {node.disabled = true;});
        try {await post(command); await refresh(); status.textContent = '保存しました。';}
        catch (error) {status.textContent = error.aliasUiSafe === true ? error.message : '結果を確認できません。再送せず一覧を更新してください。';}
        finally {
            busy = false; panel.querySelectorAll('button,input').forEach(node => {node.disabled = false;});
            if (!preferencesLoaded) document.getElementById('mail-aliases-preferences').querySelectorAll('button,input').forEach(node => {node.disabled = true;});
        }
    }
    rcmail.addEventListener('init', function () {
        if (!document.getElementById('mail-aliases-panel')) return;
        document.getElementById('mail-aliases-preferences').addEventListener('submit', function (event) {
            event.preventDefault();
            if (!preferencesLoaded) return;
            operate({kind: 'preferences', ignore_dots: document.getElementById('mail-aliases-ignore-dots').checked,
                allow_plus: document.getElementById('mail-aliases-allow-plus').checked});
        });
        document.getElementById('mail-aliases-create').addEventListener('submit', function (event) {
            event.preventDefault();
            const local = document.getElementById('mail-aliases-name').value;
            const canonical = local.toLowerCase().replace(/\./g, '');
            if (local.includes('.') && !window.confirm('登録する受信名（@より前）は「' + canonical + '」です。ドット付きでの受信は別の設定で有効にしてください。追加しますか？')) return;
            operate({kind: 'create', local_part: local});
        });
        document.getElementById('mail-aliases-refresh').addEventListener('click', () => {if (!busy) refresh().catch(() => {document.getElementById('mail-aliases-message').textContent = '一覧を取得できません。';});});
        refresh().catch(() => {document.getElementById('mail-aliases-message').textContent = '一覧を取得できません。';});
    });
}());
