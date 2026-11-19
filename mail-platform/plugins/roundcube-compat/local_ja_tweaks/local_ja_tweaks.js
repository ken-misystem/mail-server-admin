'use strict';

rcmail.addEventListener('init', () => {
    if (rcmail.task !== 'settings') return;
    const choices = [
        ['forward_action', '受信メールの転送方法'],
        ['action_target', '転送先メールアドレス'],
        ['forward_status', '転送'],
    ];
    const elements = choices.map(([id]) => document.getElementById(id));
    if (elements.some(element => !element)) return;
    const table = elements[0].closest('table');
    if (!table || !elements.every(element => table.contains(element))) return;
    table.classList.add('mi-japanese-forwarding');
    table.style.width = '100%';
    elements.forEach((element, index) => {
        element.setAttribute('aria-label', choices[index][1]);
        element.style.maxWidth = '100%';
    });
    elements[1].placeholder = 'name@example.com';
});
