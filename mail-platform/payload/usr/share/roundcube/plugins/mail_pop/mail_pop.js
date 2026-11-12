(function () {
    'use strict';
    let busy = false, refreshing = false, loaded = false, canCreate = false;
    const messages = {pop_limit: '管理者が設定した上限に達しているか、取得が許可されていません。',
        pop_pause_required: '先に取得を停止してください。',
        pop_source_review_required: '接続先が変更されています。取得履歴の確認が完了するまで取得を有効にできません。',
        pop_source_password_required: '接続先・ポート・ログイン名を変更する場合は、パスワードを再入力してください。',
        result_unverified: '結果を確認できません。再送せず一覧を更新してください。'};
    const resultLabels = {ok: '取得完了', retrieved: '取得処理完了（到着は別途確認）', limit_reached: '1回の取得上限に到達（到着は別途確認）',
        unverified: '取得結果未確認', source_changed: '接続先変更・取得履歴の確認待ち', no_mail: '新着なし',
        auth_failed: '取得元の認証失敗', tls_failed: 'TLS検証失敗', delivery_failed: '配送失敗', unavailable: '取得できません', paused: '停止中', pending: '未実行'};
    function message(text) {document.getElementById('mail-pop-message').textContent = text;}
    async function post(command) {
        const response = await fetch(rcmail.url('plugin.mail_pop-rpc'), {method: 'POST', credentials: 'same-origin', cache: 'no-store',
            headers: {'Content-Type': 'application/json', 'X-Roundcube-Request': rcmail.env.request_token}, body: JSON.stringify(command)});
        const data = await response.json();
        if (!response.ok || data.ok !== true) {const e = new Error(messages[data.error_code] || '操作できません。結果不明時は再送しないでください。'); e.safe = true; throw e;}
        return data;
    }
    function button(text, action) {const b = document.createElement('button'); b.type = 'button'; b.className = 'button'; b.textContent = text; b.addEventListener('click', action); return b;}
    function runHistory(runs) {
        if (!Array.isArray(runs) || runs.length > 10) throw new Error('Invalid history');
        const box = document.createElement('section'), title = document.createElement('h3'), note = document.createElement('p');
        box.className = 'mail-pop-history'; title.textContent = '実行履歴（直近10件）';
        note.textContent = '時刻は日本時間。取得件数は取得済み履歴への追加数で、最終配送件数ではありません。不明は「—」。導入前の実行は表示されません。接続先の編集後も履歴を保持します。';
        box.append(title, note);
        if (!runs.length) {const empty = document.createElement('p'); empty.textContent = '実行履歴はまだありません。定期実行の稼働は、この表示だけでは確認できません。'; box.append(empty); return box;}
        const outcomes = {running: '実行中・結果未確認', success: '完了', no_mail: '新着なし', limit_reached: '取得上限に到達', warning: '注意', failed: '失敗'};
        const details = {smtp_reject_temporary: 'SMTP一時拒否（4xx）', smtp_reject_permanent: 'SMTP恒久拒否（5xx）', smtp_reject_mixed: 'SMTP一時・恒久拒否を記録', smtp_connect_failed: 'SMTP接続失敗', smtp_failure_unclassified: 'SMTP処理失敗（応答コード未分類）', smtp_legacy_unverified: '旧形式SMTP記録（拒否・失敗は未確認）', diagnostic_incomplete: '診断出力上限のため一部未確認', retry_wait: '終了2の通信エラー後の再試行待ち（今回は取得なし）', retry_state_changed: '再試行対象の履歴が変更されています', retry_reserved: '未完了のため再試行禁止', retry_blocked: '自動再試行対象外', socket_unclassified: 'ソケット通信エラー（詳細理由未分類）', socket_connect_timeout: '接続確立の応答待ちで時間切れ', socket_server_timeout: 'POPサーバー応答待ちで時間切れ', socket_refused: '接続を拒否されました', socket_reset: '接続がリセットされました', socket_eof: '接続が閉じられました', network_unreachable: 'ネットワークに到達できません', host_unreachable: '接続先に到達できません', dns_temporary: '一時的な名前解決エラー', uidl_write_failed: 'UIDL保存エラー（自動再試行禁止）', smtp_timeout: 'SMTP応答待ちで時間切れ', none: '—', smtp_observed: '旧形式：SMTP関連記録（拒否・失敗は未確認）', auth_failed: '取得元の認証失敗', tls_failed: 'TLS検証・接続失敗',
            connection_failed: '接続失敗', timeout: '時間切れ', protocol_failed: 'POP通信エラー', native_failed: '取得処理エラー', preflight_failed: '事前確認で停止',
            source_not_allowed: '停止中または取得が許可されていません', history_unverified: '取得件数を確認できません', result_unverified: '結果の保存を確認できません', interrupted: '処理中断'};
        const phases = {preconditions: '事前確認', policy: 'アカウント確認', binding: '接続先・履歴確認', private_config: '接続準備', native_fetch: '取得', result_update: '結果保存', complete: '完了'};
        const table = document.createElement('table'), head = document.createElement('thead'), body = document.createElement('tbody'), heading = document.createElement('tr');
        for (const label of ['開始（JST）', '終了（JST）', '取得件数', '結果', '詳細']) {const th = document.createElement('th'); th.scope = 'col'; th.textContent = label; heading.append(th);}
        head.append(heading); table.append(head, body);
        function stamp(value) {
            if (value === null) return '—';
            if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value) || !Number.isFinite(Date.parse(value))) throw new Error('Invalid time');
            return new Intl.DateTimeFormat('ja-JP', {timeZone: 'Asia/Tokyo', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'}).format(new Date(value));
        }
        for (const run of runs) {
            if (!Object.hasOwn(outcomes, run.outcome) || !Object.hasOwn(details, run.detail_code) || !Object.hasOwn(phases, run.phase)
                || !(run.fetched_count === null || Number.isInteger(run.fetched_count) && run.fetched_count >= 0 && run.fetched_count <= 50)
                || !(run.native_exit === null || Number.isInteger(run.native_exit) && run.native_exit >= 0 && run.native_exit <= 255)) throw new Error('Invalid run');
            const tr = document.createElement('tr'); tr.className = 'mail-pop-run-' + run.outcome;
            let outcome = outcomes[run.outcome];
            if (run.outcome === 'running' && Date.now() - Date.parse(run.started_at) > 20 * 60 * 1000) outcome = '未完了（中断・結果未確認）';
            for (const text of [stamp(run.started_at), stamp(run.finished_at), run.fetched_count === null ? '—' : run.fetched_count + ' 件', outcome,
                details[run.detail_code] + '／' + phases[run.phase] + (run.native_exit === null ? '' : '／終了コード ' + run.native_exit)]) {
                const td = document.createElement('td'); td.textContent = text; tr.append(td);
            }
            body.append(tr);
        }
        const scroll = document.createElement('div'); scroll.className = 'mail-pop-history-scroll'; scroll.append(table); box.append(scroll); return box;
    }
    function controls() {
        document.querySelectorAll('#mail-pop-panel button, #mail-pop-panel input, #mail-pop-panel select').forEach(n => {n.disabled = busy || refreshing || !loaded;});
        document.getElementById('mail-pop-refresh').disabled = busy || refreshing;
        document.querySelectorAll('[data-pop-requires-permission]').forEach(n => {n.disabled = true;});
        document.querySelectorAll('[data-pop-requires-review]').forEach(n => {n.disabled = true;});
        document.querySelectorAll('#mail-pop-create button, #mail-pop-create input, #mail-pop-create select').forEach(n => {n.disabled = busy || refreshing || !loaded || !canCreate;});
    }
    function editor(account, limit) {
        const details = document.createElement('details'), summary = document.createElement('summary'), form = document.createElement('form');
        summary.textContent = '編集'; form.id = 'pop-edit-form-' + account.id; form.name = form.id; form.method = 'post'; form.className = 'mail-pop-edit-form'; details.append(summary, form);
        const fields = {};
        for (const [key, title, value, type, maximum] of [
            ['label', '表示名', account.label, 'text', 128], ['host', 'POPホスト名（ASCII）', account.remote_host, 'text', 253],
            ['port', 'TLSポート', String(account.remote_port), 'number', null], ['username', '取得元のログイン名', account.remote_username, 'text', 320],
            ['password', '新しい取得元パスワード', '', 'password', null]]) {
            const p = document.createElement('p'), label = document.createElement('label'), input = document.createElement('input');
            input.id = 'pop-edit-' + key + '-' + account.id; input.name = key; input.type = type; input.value = value;
            input.autocomplete = key === 'password' ? 'current-password' : key === 'username' ? 'username' : 'off'; input.required = key !== 'password';
            if (maximum !== null) input.maxLength = maximum;
            if (key === 'port') {input.min = '1'; input.max = '65535'; input.step = '1';}
            if (limit === 0) input.dataset.popRequiresPermission = '1';
            label.htmlFor = input.id; label.textContent = title; p.append(label, input); form.append(p); fields[key] = input;
        }
        const note = document.createElement('p');
        note.textContent = '保存すると停止します。同じ取得元ならパスワード空欄で維持します。接続先・ポート・ログイン名の変更にはパスワード再入力が必要です。旧履歴は残し、履歴確認まで取得再開を止めます。開始済みの取得は完了する場合があります。';
        const submit = document.createElement('button'); submit.type = 'submit'; submit.className = 'button mainaction'; submit.textContent = '保存して停止';
        if (limit === 0) submit.dataset.popRequiresPermission = '1';
        form.append(note, submit);
        form.addEventListener('submit', event => {
            event.preventDefault(); if (busy || refreshing || !loaded || limit === 0) return;
            const changed = fields.host.value.toLowerCase() !== account.remote_host || Number(fields.port.value) !== Number(account.remote_port) || fields.username.value !== account.remote_username;
            if (changed && fields.password.value === '') {message(messages.pop_source_password_required); return;}
            if (changed && !window.confirm('接続先を変更して停止します。旧取得履歴は削除せず、履歴確認が完了するまで取得再開できません。保存しますか？')) return;
            const command = {kind: 'edit', id: account.id, host: fields.host.value, port: fields.port.value, username: fields.username.value, label: fields.label.value, password: fields.password.value};
            operate(command, () => { fields.password.value = ''; });
        });
        return details;
    }
    async function refresh() {
        if (refreshing) return;
        refreshing = true; loaded = false; controls();
        document.getElementById('mail-pop-policy').textContent = '管理者による利用許可を確認中です。確認できるまで操作できません。';
        try {
        const data = await post({kind: 'list'});
        if (!Array.isArray(data.accounts) || !data.usage
            || !Number.isSafeInteger(data.usage.count) || !Number.isSafeInteger(data.usage.limit)
            || data.usage.count < 0 || data.usage.limit < 0 || data.usage.limit > 100 || !Number.isSafeInteger(data.poll_seconds)) throw new Error('Invalid view');
        document.getElementById('mail-pop-usage').textContent = '登録数：' + data.usage.count + ' / ' + data.usage.limit + ' 件（停止中を含む）／取得間隔：' + data.poll_seconds + ' 秒';
        const policy = document.getElementById('mail-pop-policy');
        policy.textContent = data.usage.limit === 0
          ? '管理者が外部POPメール取得を許可していません（登録上限0件）。追加・有効化・取得元設定の変更はできません。利用する場合は管理者へお問い合わせください。'
          : data.usage.count >= data.usage.limit
            ? '登録上限（' + data.usage.limit + '件）に達しています。新しい取得元は追加できません。登録済み設定の編集・停止は可能です。'
            : '外部POPメール取得は許可されています。登録上限は' + data.usage.limit + '件です。';
        policy.dataset.popPolicy = data.usage.limit === 0 ? 'denied' : 'allowed';
        const list = document.getElementById('mail-pop-list'); list.replaceChildren();
        for (const account of data.accounts) {
            if (typeof account.id !== 'string' || !/^[1-9][0-9]{0,19}$/.test(account.id) || typeof account.enabled !== 'boolean') throw new Error('Invalid account');
            const row = document.createElement('div'), name = document.createElement('p'), status = document.createElement('p'); row.className = 'mail-pop-row';
            name.textContent = account.label + '：' + account.remote_username + ' @ ' + account.remote_host + ':' + account.remote_port;
            status.textContent = (account.enabled ? '有効' : '停止中') + '／最終結果：' + (resultLabels[account.last_result] || '未確認') + '／最終成功：' + (account.last_success_at || 'なし'); row.append(name, status);
            const stateButton = button(account.enabled ? '停止' : '取得を有効にする', () => {
                if (account.enabled || window.confirm('取得を有効にします。初回は取得元に残る未取得メールを取得します。')) operate({kind: 'state', id: account.id, enabled: !account.enabled});
            });
            if (!account.enabled && data.usage.limit === 0) stateButton.dataset.popRequiresPermission = '1';
            if (!account.enabled && account.last_result === 'source_changed') stateButton.dataset.popRequiresReview = '1';
            row.append(stateButton);
            row.append(button('設定を削除', () => {if (window.confirm(account.label + ' の設定を削除します。取得元・保存済みメールは削除しません。')) operate({kind: 'remove', id: account.id, confirm: 'remove'});}));
            row.append(editor(account, data.usage.limit)); row.append(runHistory(account.run_history)); list.append(row);
        }
        if (!data.accounts.length) {const p = document.createElement('p'); p.textContent = 'POPアカウントは登録されていません。'; list.append(p);}
        canCreate = data.usage.limit > 0 && data.usage.count < data.usage.limit; loaded = true;
        } finally {refreshing = false; controls();}
    }
    async function operate(command, onSaved = null) {
        if (busy || refreshing || !loaded) return; busy = true; controls();
        try {await post(command); if (onSaved) onSaved(); await refresh(); message(command.kind === 'edit' ? '保存しました。取得は停止しています。接続先を変更した場合は履歴確認が必要です。' : '保存しました。');}
        catch (e) {message(e.safe ? e.message : '結果を確認できません。再送せず一覧を更新してください。');}
        finally {delete command.password; busy = false; controls();}
    }
    rcmail.addEventListener('init', function () {
        if (!document.getElementById('mail-pop-panel')) return;
        document.getElementById('mail-pop-create').addEventListener('submit', event => {
            event.preventDefault(); if (!loaded || !canCreate || busy) return; const password = document.getElementById('mail-pop-password');
            const command = {kind: 'create', host: document.getElementById('mail-pop-host').value, port: document.getElementById('mail-pop-port').value, username: document.getElementById('mail-pop-username').value,
                label: document.getElementById('mail-pop-label').value, password: password.value}; operate(command, () => { password.value = ''; });
        });
        document.getElementById('mail-pop-refresh').addEventListener('click', () => {if (!busy) refresh().catch(() => {message('一覧を取得できません。');});});
        refresh().catch(() => {message('一覧を取得できません。');});
    });
}());
