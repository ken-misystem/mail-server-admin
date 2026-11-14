/* Original MI-SYSTEM Sieve document forms. SPDX-License-Identifier: MIT */
'use strict';
window.MiSieveEditor = class {
    constructor(container) {
        this.container = container;
        this.document = null;
        this.extensions = null;
        this.tokenNames = {
            if: '条件に一致した場合', elsif: '前の条件に一致せず、この条件に一致', else: '前の条件のいずれにも一致しない',
            allof: 'すべての条件', anyof: 'いずれかの条件', not: '条件の否定', header: 'ヘッダー', address: 'メールアドレス',
            envelope: '配送エンベロープ', exists: 'ヘッダーの存在', size: 'サイズ', body: '本文', date: 'メールの日付',
            currentdate: '現在日時', string: '文字列・変数', spamtest: '迷惑メール点数', duplicate: '重複メッセージ',
            true: '無条件で一致', false: '常に不一致（無効化）', require: '使用する拡張機能',
            fileinto: 'フォルダー保存', redirect: '転送', keep: '受信箱へ保存', discard: '破棄', stop: '処理を終了',
            reject: '受信拒否', ereject: '受信拒否', vacation: '休暇応答', setflag: 'フラグ設定', addflag: 'フラグ追加',
            removeflag: 'フラグ削除', addheader: 'ヘッダー追加', deleteheader: 'ヘッダー削除', set: '変数設定',
            notify: '通知', include: '別のルールを呼び出す', return: '呼出し元へ戻る'
        };
    }
    token(type, value, prefix = ' ') {
        return {type, value, raw: '', prefix};
    }
    atom(type, value, prefix = ' ') {
        return {token: this.token(type, value, prefix)};
    }
    command(name, argumentsList = [], body = null) {
        return {head: this.token('word', name, '\r\n'), arguments: argumentsList,
            end: this.token('punctuation', body === null ? ';' : '{', body === null ? '' : ' '), body,
            close: body === null ? null : this.token('punctuation', '}', '\r\n')};
    }
    templates() {
        const string = value => this.atom('string', value);
        const word = value => this.atom('word', value);
        const tag = value => this.atom('tag', value);
        const number = value => this.atom('number', value);
        const entries = [
            ['header', 'ヘッダー条件', [word('header'), tag(':contains'), string('Subject'), string('検索文字')]],
            ['address', 'アドレス条件', [word('address'), tag(':domain'), tag(':is'), string('From'), string('example.test')]],
            ['envelope', '配送元・配送先条件', [word('envelope'), tag(':is'), string('to'), string('owner@example.test')], 'envelope'],
            ['exists', 'ヘッダーの存在', [word('exists'), string('List-Id')]],
            ['size', 'サイズ条件', [word('size'), tag(':over'), number('1M')]],
            ['body', '本文条件', [word('body'), tag(':text'), tag(':contains'), string('検索文字')], 'body'],
            ['date', 'メールの日付条件', [word('date'), tag(':is'), string('Date'), string('date'), string('2026-01-01')], 'date'],
            ['currentdate', '現在日時条件', [word('currentdate'), tag(':is'), string('weekday'), string('1')], 'date'],
            ['string', '文字列・変数条件', [word('string'), tag(':is'), string('${name}'), string('値')], 'variables'],
            ['spamtest', '迷惑メール点数条件', [word('spamtest'), tag(':value'), string('ge'), tag(':comparator'), string('i;ascii-numeric'), string('5')], ['spamtest', 'relational', 'comparator-i;ascii-numeric']],
            ['duplicate', '重複判定条件', [word('duplicate')], 'duplicate'],
            ['true', 'すべてのメッセージ', [word('true')]],
            ['false', '無効な条件', [word('false')]]
        ];
        const conditions = entries.map(([key, label, args, extension]) => ({key: 'test-' + key, label,
            command: this.command('if', args, [this.command('keep')]), extension, condition: args}));
        const actions = [
            ['fileinto', 'フォルダー保存', [string('Junk')], 'fileinto'],
            ['fileinto', 'フォルダーへコピー', [tag(':copy'), string('Archive')], ['fileinto', 'copy']],
            ['redirect', '転送', [string('recipient@example.test')]],
            ['redirect', '転送してコピーを保持', [tag(':copy'), string('recipient@example.test')], 'copy'],
            ['reject', '受信拒否', [string('受信できません')], 'reject'],
            ['vacation', '休暇応答', [tag(':days'), number('7'), tag(':subject'), string('不在のお知らせ'),
                tag(':from'), string('owner@example.test'), tag(':addresses'), string('owner@example.test'), string('不在です。')], 'vacation'],
            ['setflag', 'フラグ設定', [string('\\Seen')], 'imap4flags'],
            ['addflag', 'フラグ追加', [string('\\Flagged')], 'imap4flags'],
            ['removeflag', 'フラグ削除', [string('\\Seen')], 'imap4flags'],
            ['addheader', 'ヘッダー追加', [string('X-Label'), string('値')], 'editheader'],
            ['deleteheader', 'ヘッダー削除', [string('X-Label')], 'editheader'],
            ['set', '変数設定', [string('name'), string('値')], 'variables'],
            ['notify', '通知', [tag(':message'), string('通知内容'), string('mailto:owner@example.test')], 'enotify'],
            ['include', '別の個人ルールを呼出し', [tag(':personal'), string('ルール名')], 'include'],
            ['keep', '受信箱へ保存', []], ['discard', '破棄', []], ['stop', '以降の処理を終了', []],
            ['return', '呼出し元へ戻る', [], 'include'],
            ['elsif', '前の条件に続く別条件', [word('true')]], ['else', 'いずれの条件にも一致しない場合', []]
        ].map(([name, label, args, extension], index) => ({key: 'action-' + index, label,
            command: this.command(name, args, ['elsif', 'else'].includes(name) ? [this.command('keep')] : null), extension}));
        return [...conditions, ...actions].filter(template => {
            const extensions = Array.isArray(template.extension) ? template.extension : [template.extension].filter(Boolean);
            return this.extensions === null || extensions.every(extension => this.extensions.includes(extension));
        });
    }
    button(label, handler) {
        const button = document.createElement('button');
        button.type = 'button'; button.className = 'button'; button.textContent = label; button.addEventListener('click', handler);
        return button;
    }
    input(label, value, handler, multiline = false) {
        const wrapper = document.createElement('label'); wrapper.append(document.createTextNode(label));
        const input = document.createElement(multiline ? 'textarea' : 'input');
        input.className = 'form-control';
        if (multiline) input.rows = 2;
        else input.type = 'text';
        input.value = value; input.addEventListener('input', () => handler(input.value)); wrapper.append(input);
        return wrapper;
    }
    select(label, entries, handler) {
        const wrapper = document.createElement('label'); wrapper.append(document.createTextNode(label));
        const select = document.createElement('select');
        select.className = 'custom-select form-control';
        for (const [value, text] of entries) {
            const option = document.createElement('option'); option.value = value; option.textContent = text; select.append(option);
        }
        wrapper.append(select, this.button('追加', () => handler(select.value)));
        return wrapper;
    }
    require(extensions) {
        if (!extensions) return;
        for (const extension of Array.isArray(extensions) ? extensions : [extensions]) {
            const exists = this.document.commands.some(command => command.head.value.toLowerCase() === 'require'
                && JSON.stringify(command.arguments).includes('"value":"' + extension + '"'));
            if (!exists) this.document.commands.unshift(this.command('require', [this.atom('string', extension)]));
        }
    }
    tokenInput(token, context = '') {
        if (token.type === 'punctuation') {
            const text = document.createElement('span'); text.textContent = token.value; return text;
        }
        const types = {string: '値', number: '数値', tag: '比較・オプション', word: '条件・処理'};
        const label = context || this.tokenNames[token.value.toLowerCase()] || types[token.type];
        return this.input(label, token.value, value => { token.value = value; }, token.type === 'string');
    }
    moveButtons(array, index) {
        const row = document.createElement('div'); row.className = 'ms-rule-actions';
        row.append(this.button('上へ', () => { if (index > 0) { [array[index - 1], array[index]] = [array[index], array[index - 1]]; this.render(); } }),
            this.button('下へ', () => { if (index < array.length - 1) { [array[index + 1], array[index]] = [array[index], array[index + 1]]; this.render(); } }),
            this.button('削除', () => { array.splice(index, 1); this.render(); }));
        return row;
    }
    argumentsView(argumentsList, allowConditions = false, grouped = false) {
        const group = document.createElement('div'); group.className = 'ms-arguments';
        argumentsList.forEach((argument, index) => {
            const row = document.createElement('div'); row.className = 'ms-argument';
            if (argument.token) row.append(this.tokenInput(argument.token));
            else {
                const label = document.createElement('strong'); label.textContent = argument.open.value === '(' ? '条件グループ' : '値の一覧';
                row.append(label, this.argumentsView(argument.items, allowConditions && argument.open.value === '(', true));
            }
            row.append(this.moveButtons(argumentsList, index)); group.append(row);
        });
        group.append(this.select('引数を追加', [['string', '文字列'], ['tag', 'オプション :contains 等'], ['number', '数値'],
            ['word', '条件名'], ['list', '複数の値'], ['group', '条件グループ'], ['comma', '区切り ,']], kind => {
            if (['list', 'group'].includes(kind)) argumentsList.push({open: this.token('punctuation', kind === 'list' ? '[' : '('),
                items: [], close: this.token('punctuation', kind === 'list' ? ']' : ')', '')});
            else argumentsList.push(this.atom(kind === 'comma' ? 'punctuation' : kind,
                {string: '', tag: ':contains', number: '1', word: 'header', comma: ','}[kind]));
            this.render();
        }));
        const conditions = this.templates().filter(template => template.condition);
        if (allowConditions) group.append(this.select('条件を追加', conditions.map(template => [template.key, template.label]), key => {
            const template = conditions.find(item => item.key === key);
            let target = argumentsList;
            if (!grouped && argumentsList.length) {
                if (argumentsList.length === 2 && ['allof', 'anyof'].includes(argumentsList[0].token?.value)
                    && argumentsList[1].open?.value === '(') target = argumentsList[1].items;
                else {
                    target = [...argumentsList];
                    argumentsList.splice(0, argumentsList.length, this.atom('word', 'allof'), {
                        open: this.token('punctuation', '('), items: target, close: this.token('punctuation', ')', '')
                    });
                }
            }
            if (target.length && target[target.length - 1].token?.value !== ',') target.push(this.atom('punctuation', ',', ''));
            target.push(...template.condition); this.require(template.extension); this.render();
        }));
        return group;
    }
    commandsView(commands) {
        const list = document.createElement('div'); list.className = 'ms-command-list';
        commands.forEach((command, index) => {
            const card = document.createElement('details'); card.className = 'ms-command';
            const summary = document.createElement('summary');
            const ruleName = command.head.prefix.match(/# rule:\[([^\r\n]*)\]/)?.[1] || '';
            const description = this.tokenNames[command.head.value.toLowerCase()] || command.head.value;
            summary.textContent = ruleName ? ruleName + ' · ' + description : description;
            const args = this.argumentsView(command.arguments, ['if', 'elsif'].includes(command.head.value.toLowerCase()));
            card.append(summary, this.tokenInput(command.head, '条件・処理名'), args);
            if (command.head.value.toLowerCase() !== 'require') {
                card.append(this.input('ルール名', ruleName, value => {
                    const label = value.replace(/[\r\n\]]/g, ' ');
                    const comment = '# rule:[' + label + ']';
                    command.head.prefix = /# rule:\[[^\r\n]*\]/.test(command.head.prefix)
                        ? command.head.prefix.replace(/# rule:\[[^\r\n]*\]/, () => comment)
                        : command.head.prefix + '\r\n' + comment + '\r\n';
                    summary.textContent = label ? label + ' · ' + description : description;
                }));
            }
            const comments = document.createElement('details');
            const title = document.createElement('summary'); title.textContent = 'ルール名・コメント';
            comments.append(title, this.input('コメントと空白（# または /* */）', command.head.prefix,
                value => { command.head.prefix = value; }, true));
            card.append(comments);
            if (command.body !== null) card.append(this.commandsView(command.body));
            card.append(this.moveButtons(commands, index), this.button('複製', () => {
                commands.splice(index + 1, 0, structuredClone(command)); this.render();
            }));
            if (!['elsif', 'else', 'require'].includes(command.head.value.toLowerCase())) {
                const disabled = command.head.value.toLowerCase() === 'if' && command.arguments.length === 1
                    && command.arguments[0].token?.value.toLowerCase() === 'false' && command.body?.length > 0;
                card.append(this.button(disabled ? 'ルールを有効に戻す' : 'ルールを無効化', () => {
                    if (disabled) commands.splice(index, 1, ...command.body);
                    else {
                        let length = 1;
                        if (command.head.value.toLowerCase() === 'if') {
                            while (['elsif', 'else'].includes(commands[index + length]?.head.value.toLowerCase())) length++;
                        }
                        const chain = commands.splice(index, length);
                        commands.splice(index, 0, this.command('if', [this.atom('word', 'false')], chain));
                    }
                    this.render();
                }));
            }
            if (command.body !== null && !['elsif', 'else'].includes(command.head.value.toLowerCase())) {
                card.append(this.button('条件全体を否定', () => {
                    command.arguments.unshift(this.atom('word', 'not')); this.render();
                }));
                for (const [name, label] of [['allof', 'すべての条件でグループ化'], ['anyof', 'いずれかの条件でグループ化']]) {
                    card.append(this.button(label, () => {
                        command.arguments = [this.atom('word', name), {open: this.token('punctuation', '('),
                            items: command.arguments, close: this.token('punctuation', ')', '')}]; this.render();
                    }));
                }
            }
            list.append(card);
        });
        const templates = this.templates();
        list.append(this.select('ルール・処理を追加', templates.map(item => [item.key, item.label]), key => {
            const template = templates.find(item => item.key === key);
            commands.push(template.command); this.require(template.extension); this.render();
        }));
        return list;
    }
    load(documentValue, extensions = null) {
        this.extensions = extensions;
        this.document = structuredClone(documentValue); this.render();
    }
    render() {
        this.container.replaceChildren(this.commandsView(this.document.commands));
    }
    value() {
        return structuredClone(this.document);
    }
};
