rcmail.addEventListener('init', function () {
    if (rcmail.task !== 'settings') {
        return;
    }

    const action = document.getElementById('forward_action');
    const target = document.getElementById('action_target');
    const targetGroup = document.getElementById('action_target_span');
    const status = document.getElementById('forward_status');

    if (!action || !target || !targetGroup || !status) {
        return;
    }

    if (document.getElementById('local_forward_grid')) {
        return;
    }

    const oldTable = action.closest('table');

    if (!oldTable) {
        return;
    }

    // Existing Roundcube controls are reused unchanged.
    target.setAttribute('aria-label', '転送先メールアドレス');
    target.setAttribute('placeholder', 'name@example.com');
    target.removeAttribute('size');

    action.style.width = '100%';
    status.style.width = '100%';

    targetGroup.style.width = '100%';
    targetGroup.style.display = 'flex';

    target.style.width = '100%';
    target.style.flex = '1 1 auto';
    target.style.minWidth = '0';

    // Rebuild the entire forwarding UI.
    const grid = document.createElement('div');
    grid.id = 'local_forward_grid';
    grid.className = 'local-forward-grid';

    function addRow(labelText, control, forId) {
        const label = document.createElement('label');
        label.className = 'local-forward-label';
        label.htmlFor = forId;
        label.textContent = labelText;

        const value = document.createElement('div');
        value.className = 'local-forward-value';
        value.appendChild(control);

        grid.appendChild(label);
        grid.appendChild(value);
    }

    addRow(
        '受信メールの転送方法：',
        action,
        'forward_action'
    );

    addRow(
        '転送先メールアドレス：',
        targetGroup,
        'action_target'
    );

    addRow(
        '転送：',
        status,
        'forward_status'
    );

    oldTable.insertAdjacentElement('beforebegin', grid);
    oldTable.remove();

    // Local responsive layout.
    if (!document.getElementById('local_forward_style')) {
        const style = document.createElement('style');
        style.id = 'local_forward_style';
        style.textContent = `
            #local_forward_grid {
                display: grid;
                grid-template-columns: 18rem minmax(20rem, 1fr);
                column-gap: 1.25rem;
                row-gap: 1rem;
                align-items: center;
                width: 100%;
                max-width: 64rem;
                margin-bottom: 1.5rem;
            }

            #local_forward_grid .local-forward-label {
                margin: 0;
                font-weight: normal;
                line-height: 1.4;
            }

            #local_forward_grid .local-forward-value {
                min-width: 0;
                width: 100%;
            }

            #local_forward_grid select,
            #local_forward_grid input {
                width: 100%;
                max-width: none;
            }

            @media (max-width: 700px) {
                #local_forward_grid {
                    grid-template-columns: 1fr;
                    row-gap: 0.45rem;
                }

                #local_forward_grid .local-forward-value {
                    margin-bottom: 0.75rem;
                }
            }
        `;
        document.head.appendChild(style);
    }
});
