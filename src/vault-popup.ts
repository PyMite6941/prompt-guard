import * as blessed from 'blessed';
import { existsSync } from 'node:fs';
import { getDefaultVaultPath, SecretVault } from './vault';

export interface VaultPopupOptions {
    passphrase?: string | undefined;
    path?: string;
    onClose?: () => void;
}

const TAG_CHOICES = ['password', 'API', 'key', 'token', 'secret', 'other'];

/**
 * Launches an interactive terminal GUI for managing vault secrets.
 *
 * Rejects with a clear message when there is no interactive terminal, so it
 * is safe to import from any harness (CI, tests, programmatic callers).
 *
 * Returns a promise that resolves when the popup is closed.
 */
export async function launchVaultPopup(options: VaultPopupOptions = {}): Promise<void> {
    const input = process.stdin;
    const output = process.stdout;

    if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== 'function') {
        throw new Error(
            'Vault popup requires an interactive terminal. Use the SecretVault API from trusted host code in non-interactive harnesses.',
        );
    }

    const vaultPath = options.path ?? getDefaultVaultPath();
    let passphrase = options.passphrase;

    if (!passphrase) {
        passphrase = await readHidden('Vault passphrase: ');
        if (!passphrase) {
            throw new Error('Vault passphrase is required.');
        }
        if (!existsSync(vaultPath)) {
            const confirmation = await readHidden('Confirm new vault passphrase: ');
            if (passphrase !== confirmation) {
                throw new Error('Passphrases did not match.');
            }
        }
    }

    const vault = await SecretVault.open({ passphrase, path: vaultPath });
    passphrase = '';
    try {
        await runPopup(vault, options.onClose);
    } finally {
        vault.close();
    }
}

/** Reads a line from the raw terminal without echo. Used only before blessed takes over. */
function readHidden(label: string): Promise<string> {
    const stdin = process.stdin;
    const stdout = process.stdout;
    return new Promise((resolve) => {
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

export function slugify(name: string): string {
    return (
        name
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .slice(0, 120)
            .replace(/-+$/, '') || 'secret'
    );
}

function runPopup(vault: SecretVault, onClose?: () => void): Promise<void> {
    const screen = blessed.screen({
        smartCSR: true,
        title: 'Prompt Guard - Vault',
        fullUnicode: true,
        dockBorders: true,
        autoPadding: true,
    });

    const header = blessed.box({
        top: 0,
        left: 0,
        right: 0,
        height: 3,
        border: { type: 'line' },
        content:
            ' {bold}Prompt Guard - Secret Vault{/bold}   {cyan-fg}Add / preview / delete encrypted secrets{/cyan-fg}',
        tags: true,
        style: { bg: 'blue', fg: 'white' },
    });

    const list = blessed.list({
        top: 3,
        left: 0,
        width: 32,
        bottom: 1,
        border: { type: 'line' },
        label: ' Secrets ',
        tags: true,
        keys: true,
        vi: true,
        mouse: true,
        style: {
            fg: 'white',
            bg: 'black',
            selected: { bg: 'blue', fg: 'white' },
        },
    });

    const main = blessed.box({
        top: 3,
        left: 32,
        right: 0,
        bottom: 1,
        border: { type: 'line' },
        scrollable: true,
        alwaysScroll: true,
        keys: true,
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
            ' {bold}Vault{/bold}   a: Add   v: Preview   d: Delete   r: Refresh   h: Help   Tab: Focus   q: Quit',
    });

    screen.append(header);
    screen.append(list);
    screen.append(main);
    screen.append(status);

    let secretIds: string[] = [];
    // True while a modal prompt is open, so global shortcuts do not fire underneath it.
    let busy = false;

    function setMain(content: string): void {
        main.setContent(content);
        main.setScrollPerc(0);
        screen.render();
    }

    function showMessage(message: string): void {
        setMain(`\n${blessed.escape(message)}\n`);
    }

    function selectedId(): string {
        return secretIds[(list as unknown as { selected: number }).selected ?? 0] ?? '';
    }

    function refreshList(keepId?: string): void {
        const previous = keepId ?? selectedId();
        const listed = vault.listSecretsWithMeta();
        secretIds = listed.map((entry) => entry.id);
        const items = listed.length
            ? listed.map(({ id, meta }) => {
                  const name = meta.name ? ` - ${blessed.escape(meta.name)}` : '';
                  const tag = meta.tag ? ` {gray-fg}[${blessed.escape(meta.tag)}]{/gray-fg}` : '';
                  return ` ${blessed.escape(id)}${name}${tag}`;
              })
            : [' {gray-fg}(no secrets stored){/gray-fg}'];
        list.setItems(items);
        const index = secretIds.indexOf(previous);
        list.select(index >= 0 ? index : 0);
        screen.render();
    }

    function uniqueId(base: string): string {
        let id = base;
        let i = 1;
        while (secretIds.includes(id)) {
            id = `${base}-${i++}`;
        }
        return id;
    }

    function showHelp(): void {
        setMain(`
{yellow-fg}Secret Vault{/yellow-fg}
{cyan-fg}─────────────────────────────────────────{/cyan-fg}

Add, preview, and delete secrets stored in your encrypted vault.

  a    Add a new secret
  v    Preview safe metadata (values are never displayed)
  d    Delete the selected secret
  r    Refresh the list
  h    Show this help
  Tab  Switch focus between the list and this pane
  q    Quit the vault popup (Esc also works)

Secret values are encrypted at rest with AES-256-GCM and are never
written to disk in plaintext.
`);
    }

    /** Single-line text input; resolves undefined when cancelled with Esc. */
    function promptText(label: string, secret = false): Promise<string | undefined> {
        return new Promise((resolve) => {
            const box = blessed.textbox({
                parent: screen,
                top: 'center',
                left: 'center',
                width: '60%',
                height: 3,
                border: { type: 'line' },
                label: ` ${label} `,
                censor: secret,
                style: { fg: 'white', bg: 'black', border: { fg: 'cyan' } },
            });
            box.focus();
            screen.render();
            box.readInput((_error, value) => {
                box.destroy();
                screen.render();
                resolve(typeof value === 'string' ? value : undefined);
            });
        });
    }

    /** Pick one option from a list; resolves undefined when cancelled with Esc. */
    function promptSelect(label: string, options: string[]): Promise<string | undefined> {
        return new Promise((resolve) => {
            const picker = blessed.list({
                parent: screen,
                top: 'center',
                left: 'center',
                width: 30,
                height: options.length + 2,
                border: { type: 'line' },
                label: ` ${label} `,
                keys: true,
                vi: true,
                mouse: true,
                items: options,
                style: {
                    fg: 'white',
                    bg: 'black',
                    border: { fg: 'cyan' },
                    selected: { bg: 'blue', fg: 'white' },
                },
            });
            let done = false;
            const finish = (value: string | undefined) => {
                if (done) return;
                done = true;
                picker.destroy();
                screen.render();
                resolve(value);
            };
            picker.on('select', (_item, index) => finish(options[index]));
            picker.key(['escape'], () => finish(undefined));
            picker.focus();
            screen.render();
        });
    }

    function confirmAction(text: string): Promise<boolean> {
        return new Promise((resolve) => {
            const question = blessed.question({
                parent: screen,
                top: 'center',
                left: 'center',
                width: '60%',
                height: 5,
                border: { type: 'line' },
                tags: true,
                style: { fg: 'white', bg: 'black', border: { fg: 'red' } },
            });
            question.ask(text, (_error, confirmed) => {
                question.destroy();
                screen.render();
                resolve(Boolean(confirmed));
            });
        });
    }

    /** Runs a modal action with global shortcuts disabled, then restores focus. */
    function modal(action: () => Promise<void>): () => void {
        return () => {
            if (busy) return;
            busy = true;
            action()
                .catch((error: unknown) => {
                    showMessage(error instanceof Error ? error.message : 'Vault operation failed.');
                })
                .finally(() => {
                    busy = false;
                    list.focus();
                    screen.render();
                });
        };
    }

    async function addSecret(): Promise<void> {
        const name = (await promptText('Secret name (e.g. NVIDIA NIM API)'))?.trim();
        if (!name) return;

        const tag = await promptSelect('Secret tag', TAG_CHOICES);
        if (tag === undefined) return;
        const finalTag = tag === 'other' ? (await promptText('Custom tag'))?.trim() : tag;
        if (!finalTag) return;

        // The ID is derived from the name: visible, but not editable.
        const id = uniqueId(slugify(name));
        setMain(
            `\nName: ${blessed.escape(name)}\nTag: ${blessed.escape(finalTag)}\nSecret ID (read-only): ${id}\n`,
        );

        const value = await promptText(`Secret value for "${name}" (hidden)`, true);
        if (value === undefined) {
            showMessage('Cancelled; nothing was stored.');
            return;
        }
        if (value.length === 0) {
            showMessage('Secret value cannot be empty.');
            return;
        }

        await vault.setSecret(id, value);
        try {
            await vault.setSecretMeta(id, { name, tag: finalTag });
        } catch (error) {
            // Do not leave a half-created entry behind when the labels are rejected.
            await vault.deleteSecret(id);
            throw error;
        }
        refreshList(id);
        showMessage(`Stored secret "${name}" (ID: ${id}).`);
    }

    async function viewSecret(): Promise<void> {
        const id = selectedId();
        if (!id) {
            showMessage('No secret selected.');
            return;
        }
        const info = (await vault.getAgentCatalog()).find((secret) => secret.id === id);
        if (!info) {
            showMessage(`Secret "${id}" was not found.`);
            return;
        }
        const meta = vault.getSecretMeta(id) ?? {};
        showMessage(
            [
                `ID: ${info.id}`,
                `Name: ${meta.name ?? '(none)'}`,
                `Tag: ${meta.tag ?? '(none)'}`,
                '',
                'Agent catalog view:',
                `  Title: ${info.title}`,
                `  Preview: ${info.preview}`,
                `  Usage: ${info.usage}`,
            ].join('\n'),
        );
    }

    async function deleteSecret(): Promise<void> {
        const id = selectedId();
        if (!id) {
            showMessage('No secret selected.');
            return;
        }
        if (!(await confirmAction(`Delete secret "${id}"? (y/n)`))) {
            showMessage('Delete cancelled.');
            return;
        }
        await vault.deleteSecret(id);
        refreshList();
        showMessage(`Deleted secret "${id}".`);
    }

    return new Promise<void>((resolve) => {
        let closed = false;
        const closePopup = () => {
            if (busy || closed) return;
            closed = true;
            screen.destroy();
            // blessed leaves stdin flowing, which would keep the process alive.
            process.stdin.pause();
            onClose?.();
            resolve();
        };

        screen.key(['escape', 'q', 'C-c'], closePopup);
        screen.key(['a'], modal(addSecret));
        screen.key(['v'], modal(viewSecret));
        screen.key(['d'], modal(deleteSecret));
        screen.key(['h', '?'], () => {
            if (!busy) showHelp();
        });
        screen.key(['r'], () => {
            if (busy) return;
            refreshList();
            showMessage('List refreshed.');
        });
        screen.key(['tab'], () => {
            if (busy) return;
            (screen.focused === list ? main : list).focus();
            screen.render();
        });

        refreshList();
        showHelp();
        list.focus();
        screen.render();
    });
}
