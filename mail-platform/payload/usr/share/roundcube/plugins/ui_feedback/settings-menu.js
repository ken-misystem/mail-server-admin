"use strict";
(function (root) {
  const groups = [
    ["基本設定", [["preferences", "基本設定"], ["identities", "差出人・署名"]]],
    ["メールの管理", [["folders", "フォルダー"], ["responses", "定型文"],
      ["plugin.managesieve", "フィルター"], ["plugin.managesieve-forward", "転送"],
      ["plugin.mail_aliases", "受信エイリアス"], ["plugin.mail_pop", "外部POPメール取得"]]],
    ["セキュリティー", [["plugin.password", "パスワード"], ["plugin.local_auth", "パスキー"],
      ["plugin.app_passwords", "アプリ用パスワード"], ["plugin.mail_client_certificates", "端末証明書"],
      ["plugin.account-recovery", "アカウント復旧"]]]
  ];
  function organize(document) {
    const menu = document.getElementById("settings-menu");
    if (!menu) return;
    menu.querySelectorAll("[data-settings-group]").forEach(n => n.remove());
    const entries = Array.from(menu.children).map(node => {
      const link = node.querySelector("a[href]");
      if (!link) return {node, action: null, link};
      let action = null;
      try { action = new URL(link.getAttribute("href"), document.baseURI).searchParams.get("_action"); } catch (_) {}
      return {node, action, link};
    });
    const used = new Set();
    function heading(title) {
      const item = document.createElement("li"), label = document.createElement("h3");
      item.dataset.settingsGroup = "1"; item.className = "mail-settings-group";
      label.textContent = title; item.append(label); menu.append(item);
    }
    groups.forEach(([title, members]) => {
      const present = members.flatMap(([action, label]) => entries.filter(e => e.action === action).map(e => ({...e, label})));
      if (!present.length) return;
      heading(title);
      present.forEach(entry => {
        entry.link.textContent = entry.label;
        if (entry.action === "identities") entry.link.title = "メールの差出人名・差出人アドレス・署名を設定します。";
        menu.append(entry.node); used.add(entry.node);
      });
    });
    const other = entries.filter(e => !used.has(e.node));
    if (other.length) { heading("その他"); other.forEach(e => menu.append(e.node)); }
    const action = root.rcmail?.env.action;
    const title = action === "preferences" ? "基本設定" : action === "identities" || action === "edit-identity" || action === "add-identity" ? "差出人・署名" : null;
    if (title) document.querySelectorAll("#layout-content > .header .header-title, #layout-content > h1.voice").forEach(n => { n.textContent = title; });
  }
  root.MailSettingsNavigation = {organize};
  if (root.rcmail) root.rcmail.addEventListener("init", () => organize(root.document));
})(typeof window !== "undefined" ? window : globalThis);
