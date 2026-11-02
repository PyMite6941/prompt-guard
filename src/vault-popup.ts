import * as blessed from 'blessed';
import { getDefaultVaultPath, SecretVault, SecretMeta } from './vault';

export interface VaultPopupOptions {
    passphrase?: string | undefined;
    path?: string;
    onClose?: () => void;
}

/**
 * Launches an interactive terminal GUI for managing vault secrets.
 *
 * - Works interactively via a blessed modal window.
 * - Falls back gracefully (rejects with a clear message) when there is no
 *   interactive terminal, so it is safe to import from any harness (CI, tests,
 *   programmatic callers) without crashing.
 *
 * Returns a promise that resolves when the popup is closed.
 */
export async function launchVaultPopup(options: VaultPopupOptions = {}): Promise<void> {
    const input = process.stdin;
    const output = process.stdout;

    if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== 'function') {
        throw new Error(
            'Vault popup requires an interactive terminal. Use "prompt-guard vault set/list/delete" in non-interactive harnesses.',
        );
    }

    const vaultPath = options.path ?? getDefaultVaultPath();
    let passphrase = options.passphrase;

    if (!passphrase) {
        passphrase = await readHidden('Vault passphrase: ');
        if (!passphrase) {
            throw new Error('Vault passphrase is required.');
        }
        if (!vaultExists(vaultPath)) {
            const confirmation = await readHidden('Confirm new vault passphrase: ');
            if (passphrase !== confirmation) {
                throw new Error('Passphrases did not match.');
            }
        }
    }

    const vault = await SecretVault.open({ passphrase, path: vaultPath });
    let passphraseCleared = false;
    try {
        await runPopup(vault, options.onClose);
    } finally {
        if (!passphraseCleared) {
            passphrase = '';
            passphraseCleared = true;
        }
        vault.close();
    }
}

function vaultExists(path: string): boolean {
    try {
        return require('node:fs').existsSync(path);
    } catch {
        return false;
    }
}

function readHidden(label: string): Promise<string> {
    const stdin = process.stdin;
    const stdout = process.stdout;
    return new Promise((resolve) => {
        if (!stdin.isTTY || !stdout.isTTY || typeof stdin.setRawMode !== 'function') {
            resolve('');
            return;
        }
        const wasRaw = stdin.isRaw;
        let value = '';
        let finished = false;
        const finish = (result: string) => {
            if (finished) return;
            finished = true;
            stdin.removeListener('data', onData);
            stdin.pause();
            stdin.setRawMode(wasRaw);
            stdout.write('\n');
            resolve(result);
        };
        const onData = (chunk: Buffer | string) => {
            for (const character of chunk.toString()) {
                if (character === '\u0003') {
                    finish('');
                    return;
                }
                if (character === '\r' || character === '\n') {
                    finish(value);
                    return;
                }
                if (character === '\u007f' || character === '\b') {
                    value = Array.from(value).slice(0, -1).join('');
                } else if (character >= ' ') {
                    value += character;
                }
            }
        };
        stdout.write(label);
        stdin.setEncoding('utf8');
        stdin.setRawMode(true);
        stdin.resume();
        stdin.on('data', onData);
    });
}

async function runPopup(vault: SecretVault, onClose?: () => void): Promise<void> {
    const screen = blessed.screen({
        smartCSR: true,
        title: 'Prompt Guard - Vault',
        fullUnicode: true,
        dockBorders: true,
        autoPadding: true,
    });

    let resolveClose: (() => void) | undefined;
    const closePopup = () => {
        screen.removeAllListeners('key');
        list.removeAllListeners('key');
        main.removeAllListeners('key');
        screen.destroy();
        if (onClose) onClose();
        resolveClose?.();
    };

    screen.key(['escape', 'q', 'C-c'], closePopup);

    const header = blessed.box({
        top: 0,
        left: 0,
        right: 0,
        height: 3,
        border: { type: 'line' },
        content: ' {bold}Prompt Guard - Secret Vault{/bold}   {cyan-fg}Add / preview / delete encrypted secrets{/cyan-fg}',
        tags: true,
        style: { bg: 'blue', fg: 'white' },
    });

    const list = blessed.list({
        top: 4,
        left: 0,
        width: 30,
        height: '100%-6',
        border: { type: 'line' },
        tags: true,
        style: {
            fg: 'white',
            bg: 'black',
            selected: { bg: 'blue', fg: 'white' },
        },
        items: [' {bold}Secrets{/bold}'],
    });

    const main = blessed.box({
        top: 4,
        left: 31,
        right: 0,
        bottom: 1,
        border: { type: 'line' },
        scrollable: true,
        alwaysScroll: true,
        tags: true,
    });

    const status = blessed.text({
        bottom: 0,
        left: 0,
        right: 0,
        height: 1,
        tags: true,
        style: { fg: 'white', bg: 'black' },
        content:
            ' {bold}Vault{/bold}   a: Add   v: Preview   d: Delete   r: Refresh   q: Quit   Tab: focus list',
    });

    screen.append(header);
    screen.append(list);
    screen.append(main);
    screen.append(status);

    let secretIds: string[] = [];
    let secretMeta: Map<string, SecretMeta> = new Map();

    function refreshList(): void {
        const listed = vault.listSecretsWithMeta();
        secretIds = listed.map((e) => e.id);
        secretMeta = new Map(listed.map((e) => [e.id, e.meta]));
        const items = listed.length
            ? listed.map((e) => {
                  const m = e.meta;
                  const name = m.name ? ` - ${m.name}` : '';
                  const tag = m.tag ? ` [${m.tag}]` : '';
                  return ` {white-fg}${e.id}{/white-fg}${name}{gray}${tag}{/gray}`;
              })
            : [' {gray}(no secrets stored){/gray}'];
        list.setItems(items);
        if (secretIds.length) list.select(0);
        screen.render();
    }

    function slugify(name: string): string {
        return name
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .slice(0, 128) || 'secret';
    }

    function uniqueId(base: string): string {
        let id = base;
        let i = 1;
        while (secretIds.includes(id)) {
            id = `${base}-${i++}`;
        }
        return id;
    }

    function restoreKeys(): void {
        screen.removeAllListeners('key');
        screen.key(['escape', 'q', 'C-c'], closePopup);
        list.key(['a'], addSecret);
        list.key(['v'], viewSecret);
        list.key(['d'], deleteSecret);
        list.key(['r'], onRefresh);
        list.key(['tab'], () => main.focus());
        main.key(['a'], addSecret);
        main.key(['v'], viewSecret);
        main.key(['d'], deleteSecret);
        main.key(['r'], onRefresh);
        main.key(['tab'], () => list.focus());
        screen.render();
    }

    function showMessage(message: string): void {
        main.setContent(`
{yellow}Message{/yellow}
{cyan}─────────────────────────────────────────{/cyan}

${message}

Press any key to return.
`);
        status.setContent(' {bold}Message{/bold}   Press any key to return   q: Quit');
        screen.removeAllListeners('key');
        screen.key(['escape', 'q', 'C-c'], closePopup);
        const once = () => {
            restoreKeys();
            list.focus();
        };
        screen.key(['any'], once);
        screen.render();
    }

    function selectedId(): string {
        return secretIds[(list as any).index ?? 0] ?? '';
    }

    function onRefresh(): void {
        refreshList();
        showMessage('List refreshed.');
    }

    function showHelp(): void {
        main.setContent(`
{yellow}Secret Vault{/yellow}
{cyan}─────────────────────────────────────────{/cyan}

Add, preview, and delete secrets stored in your encrypted vault.

Actions (focus the list with Tab, then):
  a  Add a new secret
  v  Preview safe metadata; secret values are never displayed
  d  Delete the selected secret
  r  Refresh the list
  q  Quit the vault popup

Secret values are encrypted at rest with AES-256-GCM and are never shown
on disk in plaintext.
`);
        status.setContent(' {bold}Vault Help{/bold}   Press any key to return   q: Quit');
        screen.key(['any'], () => {
            screen.removeAllListeners('key');
            screen.key(['escape', 'q', 'C-c'], closePopup);
            list.focus();
            screen.render();
        });
        screen.render();
    }

    showHelp();

    async function addSecret(): Promise<void> {
        const name = await promptInputWithDefault(
            'Secret name (e.g. NVIDIA NIM API): ',
            '',
        );
        if (!name) {
            restoreKeys();
            list.focus();
            screen.render();
            return;
        }

        const tag = await promptSelect('Secret tag', [
            'password',
            'API',
            'key',
            'token',
            'secret',
            'other',
        ]);
        if (tag === undefined) {
            restoreKeys();
            list.focus();
            screen.render();
            return;
        }
        const finalTag = tag === 'other' ? await promptInput('Custom tag: ') : tag;
        if (finalTag === undefined || finalTag === '') {
            restoreKeys();
            list.focus();
            screen.render();
            return;
        }

        // Secret ID is derived from the name: visible, but not changeable.
        const suggestedId = uniqueId(slugify(name));
        showMessage(`Name: ${name}\nTag: ${finalTag}\nSecret ID (read-only): ${suggestedId}\n\nPress any key to enter the secret value.`);
        const _ = await waitAnyKey();
        if (_ === undefined) {
            restoreKeys();
            list.focus();
            screen.render();
            return;
        }

        const value = await promptHidden(`Secret value for "${name}": `);
        if (value === undefined || value.length === 0) {
            showMessage('Secret value cannot be empty.');
            return;
        }
        try {
            await vault.setSecret(suggestedId, value);
            await vault.setSecretMeta(suggestedId, { name, tag: finalTag });
            refreshList();
            showMessage(`Stored secret "${name}" (ID: ${suggestedId}).`);
        } catch (err: any) {
            showMessage(`Failed to store secret: ${err.message}`);
        }
    }

    function waitAnyKey(): Promise<string | undefined> {
        return new Promise((resolve) => {
            const stdin = process.stdin;
            const stdout = process.stdout;
            if (!stdin.isTTY || !stdout.isTTY || typeof stdin.setRawMode !== 'function') {
                resolve(undefined);
                return;
            }
            const wasRaw = stdin.isRaw;
            let finished = false;
            const finish = (result: string | undefined) => {
                if (finished) return;
                finished = true;
                stdin.removeListener('data', onData);
                stdin.pause();
                stdin.setRawMode(wasRaw);
                stdout.write('\n');
                resolve(result);
            };
            const onData = (chunk: Buffer | string) => {
                for (const character of chunk.toString()) {
                    if (character === '\u0003') {
                        finish(undefined);
                        return;
                    }
                    if (character === '\r' || character === '\n') {
                        finish('');
                        return;
                    }
                    finish(character);
                    return;
                }
            };
            stdout.write('');
            stdin.setEncoding('utf8');
            stdin.setRawMode(true);
            stdin.resume();
            stdin.on('data', onData);
        });
    }

    function promptSelect(label: string, options: string[]): Promise<string | undefined> {
        return new Promise((resolve) => {
            const stdin = process.stdin;
            const stdout = process.stdout;
            if (!stdin.isTTY || !stdout.isTTY || typeof stdin.setRawMode !== 'function') {
                resolve(undefined);
                return;
            }
            const lines = options.map((o, i) => `  [${i + 1}] ${o}`).join('\n');
            stdout.write(`${label}\n${lines}\nSelect 1-${options.length}: `);
            const wasRaw = stdin.isRaw;
            let finished = false;
            const finish = (result: string | undefined) => {
                if (finished) return;
                finished = true;
                stdin.removeListener('data', onData);
                stdin.pause();
                stdin.setRawMode(wasRaw);
                stdout.write('\n');
                resolve(result);
            };
            const onData = (chunk: Buffer | string) => {
                for (const character of chunk.toString()) {
                    if (character === '\u0003') {
                        finish(undefined);
                        return;
                    }
                    if (character === '\r' || character === '\n') {
                        finish(undefined);
                        return;
                    }
                    const n = Number(character.trim());
                    if (Number.isInteger(n) && n >= 1 && n <= options.length) {
                        finish(options[n - 1]);
                        return;
                    }
                }
            };
            stdin.setEncoding('utf8');
            stdin.setRawMode(true);
            stdin.resume();
            stdin.on('data', onData);
        });
    }

    function promptInputWithDefault(label: string, defaultValue: string): Promise<string> {
        return new Promise((resolve) => {
            const stdin = process.stdin;
            const stdout = process.stdout;
            if (!stdin.isTTY || !stdout.isTTY || typeof stdin.setRawMode !== 'function') {
                resolve('');
                return;
            }
            const wasRaw = stdin.isRaw;
            let value = defaultValue;
            let finished = false;
            // Render the default as editable text: show default, allow backspace to clear, then type.
            stdout.write(`${label} [${defaultValue}]: `);
            const finish = (result: string) => {
                if (finished) return;
                finished = true;
                stdin.removeListener('data', onData);
                stdin.pause();
                stdin.setRawMode(wasRaw);
                stdout.write('\n');
                resolve(result);
            };
            const onData = (chunk: Buffer | string) => {
                for (const character of chunk.toString()) {
                    if (character === '\u0003') {
                        finish('');
                        return;
                    }
                    if (character === '\r' || character === '\n') {
                        finish(value);
                        return;
                    }
                    if (character === '\u007f' || character === '\b') {
                        value = Array.from(value).slice(0, -1).join('');
                    } else if (character >= ' ') {
                        value += character;
                    }
                }
            };
            stdin.setEncoding('utf8');
            stdin.setRawMode(true);
            stdin.resume();
            stdin.on('data', onData);
        });
    }

    async function viewSecret(): Promise<void> {
        const id = selectedId();
        if (!id) {
            showMessage('No secret selected.');
            return;
        }
        try {
            const info = (await vault.getAgentCatalog()).find((secret) => secret.id === id);
            if (!info) {
                showMessage('This secret is not safe to show in the agent catalog. Change its ID.');
                return;
            }
            showMessage(
                `Title: ${info.title}\nID: ${info.id}\nPreview: ${info.preview}\nHow to use: ${info.usage}`,
            );
        } catch (err: any) {
            showMessage(`Could not read secret: ${err.message}`);
        }
    }

    async function deleteSecret(): Promise<void> {
        const id = selectedId();
        if (!id) {
            showMessage('No secret selected.');
            return;
        }
        const confirmed = await confirmAction(`Delete secret "${id}"? (y/n): `);
        if (!confirmed) return;
        try {
            await vault.deleteSecret(id);
            refreshList();
            showMessage(`Deleted secret "${id}".`);
        } catch (err: any) {
            showMessage(`Failed to delete secret: ${err.message}`);
        }
    }

    list.on('select', () => {
        refreshList();
    });

    list.key(['a'], addSecret);
    list.key(['v'], viewSecret);
    list.key(['d'], deleteSecret);
    list.key(['r'], () => {
        refreshList();
        showMessage('List refreshed.');
    });
    list.key(['tab'], () => {
        main.focus();
    });

    main.key(['a'], addSecret);
    main.key(['v'], viewSecret);
    main.key(['d'], deleteSecret);
    main.key(['r'], () => {
        refreshList();
        showMessage('List refreshed.');
    });
    main.key(['tab'], () => {
        list.focus();
    });

    refreshList();
    list.focus();
    screen.render();

    return new Promise<void>((resolve) => {
        resolveClose = resolve;
    });
}

function promptInput(label: string): Promise<string> {
    return new Promise((resolve) => {
        const inputBox = blessed.textbox({
            top: 'center',
            left: 'center',
            width: 50,
            height: 3,
            border: { type: 'line' },
            label: ` ${label} `,
            inputOnFocus: true,
            style: { fg: 'white', bg: 'black', border: { fg: 'cyan' } },
        });

        const screen = inputBox.screen as blessed.Widgets.Screen;
        inputBox.key(['enter'], () => {
            const value = inputBox.getValue().trim();
            inputBox.destroy();
            screen.render();
            resolve(value);
        });
        inputBox.key(['escape'], () => {
            inputBox.destroy();
            screen.render();
            resolve('');
        });

        screen.append(inputBox);
        inputBox.focus();
        screen.render();
    });
}

function promptHidden(label: string): Promise<string | undefined> {
    return new Promise((resolve) => {
        const stdin = process.stdin;
        const stdout = process.stdout;
        if (!stdin.isTTY || !stdout.isTTY || typeof stdin.setRawMode !== 'function') {
            resolve(undefined);
            return;
        }
        const wasRaw = stdin.isRaw;
        let value = '';
        let finished = false;
        const finish = (result: string | undefined) => {
            if (finished) return;
            finished = true;
            stdin.removeListener('data', onData);
            stdin.pause();
            stdin.setRawMode(wasRaw);
            stdout.write('\n');
            resolve(result);
        };
        const onData = (chunk: Buffer | string) => {
            for (const character of chunk.toString()) {
                if (character === '\u0003') {
                    finish(undefined);
                    return;
                }
                if (character === '\r' || character === '\n') {
                    finish(value);
                    return;
                }
                if (character === '\u007f' || character === '\b') {
                    value = Array.from(value).slice(0, -1).join('');
                } else if (character >= ' ') {
                    value += character;
                }
            }
        };
        stdout.write(label);
        stdin.setEncoding('utf8');
        stdin.setRawMode(true);
        stdin.resume();
        stdin.on('data', onData);
    });
}

function confirmAction(label: string): Promise<boolean> {
    return new Promise((resolve) => {
        const stdin = process.stdin;
        const stdout = process.stdout;
        if (!stdin.isTTY || !stdout.isTTY || typeof stdin.setRawMode !== 'function') {
            resolve(false);
            return;
        }
        const wasRaw = stdin.isRaw;
        let finished = false;
        const finish = (result: boolean) => {
            if (finished) return;
            finished = true;
            stdin.removeListener('data', onData);
            stdin.pause();
            stdin.setRawMode(wasRaw);
            stdout.write('\n');
            resolve(result);
        };
        const onData = (chunk: Buffer | string) => {
            for (const character of chunk.toString()) {
                if (character === '\u0003') {
                    finish(false);
                    return;
                }
                if (character === '\r' || character === '\n') {
                    finish(false);
                    return;
                }
                if (character === 'y' || character === 'Y') {
                    finish(true);
                    return;
                }
                if (character === 'n' || character === 'N') {
                    finish(false);
                    return;
                }
            }
        };
        stdout.write(label);
        stdin.setEncoding('utf8');
        stdin.setRawMode(true);
        stdin.resume();
        stdin.on('data', onData);
    });
}
