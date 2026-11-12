/* Read-only guide. Never reads, requests, copies or stores any secret. */
(function () {
    'use strict';
    function initializeTabs(root) {
        var mainTabs = document.getElementById('help-main-tabs');
        var clientTabs = document.getElementById('help-client-tabs');
        var mainPanels = Array.from(root.querySelectorAll('.help-panel'));
        var clientPanels = Array.from(root.querySelectorAll('.help-client-panel'));
        if (!mainTabs || !clientTabs || mainPanels.length !== 5 || clientPanels.length !== 6) return;
        var selectedClient = 'fair';
        var mainButtons = Array.from(mainTabs.querySelectorAll('[role="tab"]'));
        var clientButtons = Array.from(clientTabs.querySelectorAll('[role="tab"]'));
        var mainNames = mainPanels.map(function (panel) { return panel.id; });
        var clientNames = clientPanels.map(function (panel) { return panel.id; });

        function update(buttons, panels, selected) {
            buttons.forEach(function (button) {
                var active = button.getAttribute('aria-controls') === selected;
                button.setAttribute('aria-selected', String(active));
                button.tabIndex = active ? 0 : -1;
            });
            panels.forEach(function (panel) { panel.hidden = panel.id !== selected; });
        }

        function select(name, changeAddress) {
            var mainName = name;
            if (clientNames.indexOf(name) !== -1) {
                selectedClient = name;
                mainName = 'clients';
            }
            if (mainNames.indexOf(mainName) === -1) mainName = 'connection';
            update(mainButtons, mainPanels, mainName);
            update(clientButtons, clientPanels, selectedClient);
            if (changeAddress) window.history.replaceState(null, '', '#' + name);
        }

        function wire(tablist, buttons) {
            buttons.forEach(function (button) {
                button.addEventListener('click', function () {
                    select(button.getAttribute('aria-controls'), true);
                });
            });
            tablist.addEventListener('keydown', function (event) {
                var index = buttons.indexOf(event.target);
                if (index === -1) return;
                var next = index;
                if (event.key === 'ArrowRight') next = (index + 1) % buttons.length;
                else if (event.key === 'ArrowLeft') next = (index + buttons.length - 1) % buttons.length;
                else if (event.key === 'Home') next = 0;
                else if (event.key === 'End') next = buttons.length - 1;
                else return;
                event.preventDefault();
                select(buttons[next].getAttribute('aria-controls'), true);
                buttons[next].focus();
            });
        }

        wire(mainTabs, mainButtons);
        wire(clientTabs, clientButtons);
        root.addEventListener('click', function (event) {
            var anchor = event.target.closest('a[href^="#"]');
            if (!anchor || !root.contains(anchor)) return;
            var name = anchor.getAttribute('href').slice(1);
            if (mainNames.indexOf(name) === -1 && clientNames.indexOf(name) === -1) return;
            event.preventDefault();
            select(name, true);
            document.getElementById(name).focus();
        });
        window.addEventListener('hashchange', function () { select(window.location.hash.slice(1), false); });
        mainTabs.hidden = false;
        clientTabs.hidden = false;
        root.classList.add('help-tabs-ready');
        select(window.location.hash.slice(1), false);
    }

    function initialize() {
        var root = document.getElementById('mail-app-help');
        if (!root || root.dataset.ready === 'yes') return;
        root.dataset.ready = 'yes';
        initializeTabs(root);
        var env = window.rcmail && window.rcmail.env;
        var username = env && typeof env.mail_app_help_username === 'string' ? env.mail_app_help_username : '';
        root.querySelectorAll('[data-help-username]').forEach(function (node) {
            node.textContent = username || 'Roundcubeにログインしている本人のメールアドレス';
        });
        root.querySelectorAll('[data-help-copy]').forEach(function (button) {
            button.hidden = !(navigator.clipboard && window.isSecureContext);
            button.addEventListener('click', function () {
                var value = button.dataset.helpCopy === 'username' ? username : 'mx.mi-sys.jp';
                var status = document.getElementById('mail-help-status');
                if (!value || !navigator.clipboard) return;
                navigator.clipboard.writeText(value).then(function () {
                    status.textContent = 'コピーしました。';
                }, function () {
                    status.textContent = 'コピーできませんでした。表示された文字を選択してコピーしてください。';
                });
            });
        });
    }
    if (window.rcmail && typeof window.rcmail.addEventListener === 'function') window.rcmail.addEventListener('init', initialize);
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize);
    else initialize();
}());
