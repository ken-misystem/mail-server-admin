"use strict";
(function (root) {
  const certificateStates = Object.freeze({active:'有効',revoked:'無効',pending:'発行処理中',
    revoke_pending:'無効化の反映待ち',issuance_unknown:'発行結果の確認が必要',failed:'発行失敗',expired:'期限切れ'});
  const componentNames = Object.freeze({crl:'失効一覧',existing_sessions:'既存の接続',imaps:'IMAP受信',
    pop3s:'POP受信',resumption:'接続の再開',submission:'SMTP送信',material_retired:'秘密情報の破棄'});
  class DeviceCertificatesUI {
    constructor(panel, transport) {
      this.panel = panel; this.transport = transport; this.busy = false; this.ticket = null; this.next = null; this.readiness = 'unknown'; this.backendReady = false;
      const find = selector => panel.querySelector(selector);
      this.find = find; this.result = find('[data-cert-result]'); this.rows = find('[data-cert-rows]');
      this.deliveryDialog = find('[data-cert-delivery-dialog]'); this.delivery = null; this.pendingDeliveryFocus = null;
      this.deliveryDialog.addEventListener('cancel', event => { event.preventDefault(); this.dismissDelivery(); });
      find('[data-cert-discard]').addEventListener('click', () => this.dismissDelivery());
      find('[data-cert-delivery-close]').addEventListener('click', () => this.dismissDelivery());
      this.listing = find('[data-cert-list]'); this.listSummary = find('[data-cert-list-summary]');
      this.pageCount = null;
      this.listing.open = false;
      this.listing.addEventListener('toggle', () => this.listCaption());
      this.listCaption();
      const owner = find('[data-cert-owner]'); if (owner) owner.value = root.rcmail?.env.mail_client_certificates_owner_username || '';
      find('[data-cert-refresh]').addEventListener('click', () => this.operation(() => this.list()));
      find('[data-cert-next]').addEventListener('click', () => { if (this.next) this.operation(() => this.list(this.next)); });
      find('[data-cert-form]').addEventListener('submit', event => {
        event.preventDefault(); this.issue(find('[data-cert-label]').value, find('[data-cert-password]').value);
      });
      const password = find('[data-cert-password]');
      ['input', 'change'].forEach(event => password.addEventListener(event, () => password.setCustomValidity('')));
      find('[data-cert-download]').addEventListener('click', () => this.download());
      root.addEventListener?.('pagehide', () => { password.value = ''; this.ticket = null; });
      root.addEventListener?.('beforeunload', event => { if (this.ticket) { event.preventDefault(); event.returnValue = ''; } });
      this.controls();
    }
    listCaption() {
      const count = Number.isInteger(this.pageCount) ? '（表示中' + this.pageCount + '件' + (this.next ? '・続きあり' : '') + '）' : '';
      this.listSummary.textContent = (this.listing.open ? '− ' : '＋ ') + '登録済み証明書' + count;
    }
    notify(text, failed = false) {
      this.result.textContent = text; this.result.setAttribute('role', failed ? 'alert' : 'status');
      if (this.deliveryDialog.open) this.find('[data-cert-delivery-result]').textContent = text;
    }
    openDelivery(ticket) {
      this.delivery = {device_id:ticket.device_id, stage:'ready'};
      this.find('[data-cert-delivery-result]').textContent = 'P12は1回だけ取得できます。取得せずに閉じる場合、この証明書を無効化します。';
      this.find('[data-cert-discard]').hidden = false; this.find('[data-cert-delivery-close]').hidden = true;
      this.deliveryDialog.showModal(); this.controls(); this.pendingDeliveryFocus = '[data-cert-download]';
    }
    applyPendingDeliveryFocus() {
      if (this.busy) return;
      const selector = this.pendingDeliveryFocus; this.pendingDeliveryFocus = null;
      if (!selector || !this.deliveryDialog.open) return;
      const button = this.find(selector);
      if (button && !button.disabled && !button.hidden) button.focus();
    }
    async dismissDelivery() {
      if (this.busy || !this.delivery) return;
      if (this.delivery.stage === 'sent') { this.deliveryDialog.close(); this.delivery = null; return; }
      if (this.readiness !== 'ready' || !this.backendReady) {
        this.notify('無効化を開始できません。完了は確認していません。通信を確認してください。未取得のP12には既存の有効期限が適用されます。',true); return;
      }
      const device = this.delivery.device_id;
      await this.revoke(device, () => {
        this.deliveryDialog.close(); this.delivery = null;
      });
    }
    controls() {
      const blocked = this.busy || this.readiness !== 'ready' || !this.backendReady;
      this.find('[data-cert-fields]').disabled = blocked;
      this.panel.querySelectorAll('[data-cert-revoke]').forEach(button => { button.disabled = blocked; });
      this.find('[data-cert-refresh]').disabled = this.busy;
      this.find('[data-cert-next]').disabled = this.busy || !this.next;
      this.find('[data-cert-download]').disabled = this.busy || !this.ticket;
      this.find('[data-cert-discard]').disabled = this.busy || blocked;
      this.find('[data-cert-delivery-close]').disabled = this.busy;
      const notes = {unknown: 'パスキー登録状態を確認できません。一覧を更新してください。発行・無効化は停止しています。',
        missing: '有効なパスキーが未登録です。先にこのアカウントのパスキーを登録してください。発行・無効化はできません。',
        unsupported: 'このブラウザーではパスキーを使用できません。対応する環境で操作してください。',
        ready: 'パスキー登録済みです。本人確認後は同じログイン中、最長15分間は本人管理全体の再認証を省略します。ログアウト・認証設定の変更等では再確認が必要です。'};
      this.find('[data-cert-prerequisite]').textContent = this.readiness === 'ready' && !this.backendReady
        ? 'パスキー登録済みです。証明書サービスの状態を確認できないため、発行・無効化を停止しています。パスキーの再登録は不要です。'
        : notes[this.readiness];
    }
    async operation(work) {
      if (this.busy) return;
      this.busy = true; this.panel.setAttribute('aria-busy', 'true'); this.controls();
      try { await work(); }
      catch (error) {
        this.pendingDeliveryFocus = null; this.ticket = null;
        if (this.delivery && this.delivery.stage === 'downloading') this.delivery.stage = 'uncertain';
        const downloadErrors = {
          p12_request_invalid:'P12の取得情報を確認できません。一覧を更新して状態を確認してください。',
          p12_request_rejected:'P12の取得要求がサーバーに拒否されました。再操作せず、管理者へ連絡してください。',
          p12_response_unverified:'P12を受信できませんでした。一覧で証明書の状態を確認してください。自動再試行は行いません。',
          p12_length_unverified:'P12の受信データの完全性を確認できません。再取得せず、無効化して再発行してください。',
          download_unavailable:'この画面にはP12の取得情報がありません。発行直後の画面で期限内に取得してください。'
        };
        this.notify(downloadErrors[error?.message] || (error?.name === 'NotAllowedError' || error?.name === 'AbortError'
          ? 'パスキー認証を取消したか、認証が完了しませんでした。発行・無効化の完了は確認していません。'
          : '処理結果を確認できません。一覧を更新してください。自動再試行は行いません。'), true);
      } finally { this.busy = false; this.panel.setAttribute('aria-busy', 'false'); this.controls(); this.applyPendingDeliveryFocus(); }
    }
    async list(cursor = null) {
      this.readiness = 'unknown'; this.backendReady = false; this.controls();
      // Each independent read is attempted exactly once. List failure must not skip Passkey status.
      const [metadata, listing] = await Promise.allSettled([
        this.transport.readiness(), this.transport.post('list', cursor ? {cursor} : {})
      ]);
      if (metadata.status === 'fulfilled') {
        this.readiness = root.MailOwnerPrerequisites.certificateState(metadata.value,
          Boolean(root.isSecureContext && root.PublicKeyCredential && root.navigator?.credentials));
      }
      if (listing.status !== 'fulfilled' || !Array.isArray(listing.value?.items) || listing.value.items.length > 10) {
        this.next = null; this.controls();
        this.notify(this.readiness === 'ready'
          ? 'パスキー登録は確認できましたが、端末証明書一覧を取得できません。パスキーの再登録は不要です。'
          : '端末証明書一覧を取得できません。パスキーの状態は上の案内を確認してください。', true);
        return;
      }
      const response = listing.value; this.backendReady = true;
      this.notify(response.items.length === 0
        ? (cursor ? 'このページに端末証明書はありません。' : '端末証明書はまだ発行されていません。下のフォームから初回発行できます。')
        : '端末証明書の一覧を取得しました。');
      this.rows.replaceChildren(); this.next = response.next || null;
      this.pageCount = response.items.length; this.listCaption();
      response.items.forEach(row => {
        const entry = this.panel.ownerDocument.createElement('li'), label = this.panel.ownerDocument.createElement('span');
        label.textContent = row.label + ' — ' + (certificateStates[row.state] || '状態を確認できません'); entry.append(label);
        if (row.state !== 'revoked') {
          const button = this.panel.ownerDocument.createElement('button'); button.type = 'button'; button.textContent = '無効化する';
          button.setAttribute('data-cert-revoke', ''); button.disabled = true;
          button.addEventListener('click', () => this.revoke(row.device_id)); entry.append(button);
        }
        if (row.revocation_pending_components?.length) {
          const pending = this.panel.ownerDocument.createElement('span'); pending.textContent = '反映待ち: ' + row.revocation_pending_components.map(name => componentNames[name] || 'その他の反映処理').join('、'); entry.append(pending);
        }
        this.rows.append(entry);
      });
      this.controls();
    }
    issue(label, password) {
      if (this.busy || this.readiness !== 'ready' || !this.backendReady) { this.controls(); return Promise.resolve(); }
      if (this.ticket || this.delivery) { this.notify('先に発行済みP12をダウンロードするか、その証明書を無効化してください。画面を離れると取得できなくなります。', true); return Promise.resolve(); }
      if (typeof this.deliveryDialog.showModal !== 'function') {
        this.notify('このブラウザーはP12取得ダイアログに対応していません。対応するブラウザーを使用してください。発行は行っていません。',true); return Promise.resolve();
      }
      const field = this.find('[data-cert-password]'), error = root.MailOwnerPrerequisites.passwordError(password);
      field.setCustomValidity(error);
      if (error) { this.notify(error, true); field.reportValidity(); return Promise.resolve(); }
      if (!label.trim()) { this.notify('端末名は必須です。', true); this.find('[data-cert-label]').reportValidity(); return Promise.resolve(); }
      if (!this.find('[data-cert-form]').reportValidity()) return Promise.resolve();
      return this.operation(async () => {
        this.ticket = null; this.notify('パスキー認証を待っています。');
        const start = await this.transport.post('issue_options', {label, request_id: root.crypto.randomUUID()});
        const assertion = start.authentication_required === false ? null : await this.transport.assert(start.publicKey);
        this.notify('発行中です。完了するまで再操作しないでください。');
        const result = await this.transport.post('issue_finish', {action_id: start.action_id, assertion, p12_password: password});
        password = null;
        if (result.state !== 'active' || !result.download_handle) throw new Error('issuance_unverified');
        // Leave the field intact through approval/submission. Clear only after confirmed success or page exit.
        field.value = ''; field.setCustomValidity('');
        const ticket = {device_id: result.device_id, download_handle: result.download_handle, expires_at: result.download_expires_at};
        try { await this.list(); } catch (_) { this.readiness = 'unknown'; }
        this.ticket = ticket; this.openDelivery(ticket);
        const deadline = Number.isInteger(result.download_expires_at) ? new Date(result.download_expires_at * 1000).toLocaleTimeString() : '表示された期限';
        this.notify('発行しました。この画面を閉じたり再読み込みせず、' + deadline + 'までにP12を1回だけダウンロードしてください（最大5分）。保護パスワードとともに安全に保管してください。期限内に送信が完了しなかった証明書は自動で無効化します。');
      });
    }
    download() {
      return this.operation(async () => {
        if (!this.ticket) throw new Error('download_unavailable');
        const ticket = this.ticket; this.ticket = null; if (this.delivery) this.delivery.stage = 'downloading'; this.controls(); this.notify('P12をダウンロードしています。');
        await this.transport.downloadPost(ticket);
        if (this.delivery) this.delivery.stage = 'sent';
        this.find('[data-cert-discard]').hidden = true; this.find('[data-cert-delivery-close]').hidden = false;
        this.pendingDeliveryFocus = '[data-cert-delivery-close]';
        this.notify('P12のダウンロード応答が完了しました。端末にファイルが保存されたことを確認してください。再ダウンロードはできません。サーバーは端末への保存完了を確認できないため、保存できなかった場合は無効化して再発行してください。');
      });
    }
    revoke(device_id, afterAccepted = null) {
      if (this.busy || this.readiness !== 'ready' || !this.backendReady) { this.controls(); return Promise.resolve(); }
      return this.operation(async () => {
        this.ticket = null; this.notify('パスキー認証を待っています。');
        const start = await this.transport.post('revoke_options', {device_id, request_id: root.crypto.randomUUID()});
        const assertion = start.authentication_required === false ? null : await this.transport.assert(start.publicKey);
        const result = await this.transport.post('revoke_finish', {action_id: start.action_id, assertion});
        if (!['revoked', 'revoke_pending'].includes(result.state)) throw new Error('revocation_unverified');
        if (afterAccepted) afterAccepted();
        await this.list(); this.notify(result.state === 'revoked' ? '無効化の反映を確認しました。履歴は保持します。' : '新規認可は拒否済みです。失効反映は確認中です。');
      });
    }
  }
  root.DeviceCertificatesUI = DeviceCertificatesUI;
  if (typeof module !== 'undefined') module.exports = DeviceCertificatesUI;
})(typeof window !== 'undefined' ? window : globalThis);
