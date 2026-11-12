(() => {
  'use strict';
  let busy = false, cursor = null;
  const byId = id => document.getElementById(id);
  function message(text) { const box = byId('app-password-result'); box.textContent = text; box.focus(); }
  function clearOnce() { const field = byId('app-password-once'); field.value = ''; field.type = 'password'; byId('app-password-once-panel').hidden = true; byId('app-password-reveal').textContent = '表示する'; }
  function controls() { document.querySelectorAll('#app-password-panel button').forEach(button => { button.disabled = busy; }); }
  function confirmed() {
    const password = byId('app-password-confirm');
    if (password.value === '') { message('現在のログインパスワードは必須です。'); password.reportValidity(); return false; }
    return true;
  }
  async function request(operation, extra = {}) {
    if (busy) return null;
    busy = true; const password = byId('app-password-confirm');
    const data = new URLSearchParams({_token: rcmail.env.request_token, _operation: operation, ...extra});
    if (!['list','verification'].includes(operation)) {
      try {
        const status = await fetch(rcmail.env.app_passwords_api, {method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'X-Roundcube-Request':rcmail.env.request_token},body:new URLSearchParams({_token:rcmail.env.request_token,_operation:'verification'})});
        const proof=await status.json();
        if(!status.ok || !proof.ok || typeof proof.value?.authentication_required!=='boolean') throw new Error('verification_unavailable');
        if(proof.value.authentication_required){if(!confirmed()){busy=false;return null;}data.set('_owner_password',password.value);}
      } catch (_) {busy=false;message('本人確認の状態を確認できません。保存せずに一覧を更新してください。');return null;}
    }
    clearOnce(); controls(); message('処理中です。');
    try {
      const reply = await fetch(rcmail.env.app_passwords_api, {method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers:{'X-Roundcube-Request':rcmail.env.request_token}, body: data});
      data.delete('_owner_password'); const result = await reply.json();
      if (!reply.ok || !result.ok) throw new Error(result.error === 'owner_confirmation_required' ? 'owner_confirmation_required' : 'operation_unverified');
      if (operation !== 'list') password.value = '';
      return result.value;
    } catch (error) {
      message(error.message === 'owner_confirmation_required' ? '現在のログインパスワードを確認してください。' : '処理結果を確認できません。自動再試行はしません。一覧を更新してください。'); return null;
    } finally { data.delete('_owner_password'); busy = false; controls(); }
  }
  async function listing(next = false) {
    const value = await request('list', {_cursor: next ? cursor || '' : ''}); if (!value) return;
    const list = byId('app-password-list'); if (!next) list.replaceChildren();
    for (const item of value.items) {
      const row = document.createElement('li'), text = document.createElement('span');
      text.textContent = `${item.label} ／ ${item.revoked_at ? '失効済み' : '有効'} ／ 発行 ${item.created_at} ／ 最終使用 ${item.last_used_at || '未記録'}`; row.append(text);
      if (!item.revoked_at) {
        const button = document.createElement('button'); button.type = 'button'; button.textContent = '失効させる';
        button.onclick = async () => { if (!confirm('このアプリ用パスワードを失効させますか？')) return; if (await request('revoke', {_id: String(item.id)})) await listing(); };
        row.append(button);
      }
      list.append(row);
    }
    cursor = value.next; byId('app-password-more').hidden = !cursor; message('一覧を更新しました。');
  }
  document.addEventListener('DOMContentLoaded', () => {
    if (!byId('app-password-panel')) return;
    byId('app-password-confirm').required = false;
    byId('app-password-owner').value = rcmail.env.app_passwords_owner_username || '';
    byId('app-password-refresh').onclick = () => listing(); byId('app-password-more').onclick = () => listing(true);
    byId('app-password-issue-form').addEventListener('submit', async event => {
      event.preventDefault(); if (!byId('app-password-issue-form').reportValidity()) return;
      const value = await request('issue', {_label: byId('app-password-label').value}); if (!value) return;
      byId('app-password-once').value = value.credential; byId('app-password-once-panel').hidden = false;
      message('発行しました。今回だけ表示します。コピーまたはパスワード管理ソフトへ保存してください。');
    });
    byId('app-password-reveal').onclick = () => { const field = byId('app-password-once'); field.type = field.type === 'password' ? 'text' : 'password'; byId('app-password-reveal').textContent = field.type === 'password' ? '表示する' : '隠す'; };
    byId('app-password-copy').onclick = async () => {
      const field = byId('app-password-once'); if (!field.value) return;
      try { await navigator.clipboard.writeText(field.value); message('アプリ用パスワードをコピーしました。'); }
      catch (_) { field.focus(); field.select(); message('自動コピーできません。選択した値を手動でコピーしてください。'); }
    };
    window.addEventListener('pagehide', () => { clearOnce(); byId('app-password-confirm').value = ''; });
    controls(); listing();
  });
})();
