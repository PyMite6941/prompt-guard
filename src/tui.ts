#!/usr/bin/env node
import * as blessed from 'blessed';
import * as fs from 'fs';
import * as path from 'path';
import { scanText, ScanResult, Severity } from './scanner';
import { PII_PATTERNS } from './patterns';

class PromptGuardTUI {
    private screen: blessed.Widgets.Screen;
    private currentFile: string | null = null;
    private currentResult: ScanResult | null = null;
    private ignoreList: string[] = [];
    private minSeverity: Severity | undefined = undefined;

    private navList!: blessed.Widgets.ListElement;
    private mainBox!: blessed.Widgets.BoxElement;
    private statusBar!: blessed.Widgets.TextElement;
    private headerBox!: blessed.Widgets.BoxElement;
    private inputBox: blessed.Widgets.TextboxElement | null = null;

    constructor() {
        this.screen = blessed.screen({
            smartCSR: true,
            title: 'Prompt Guard - TUI',
            fullUnicode: true,
            dockBorders: true,
        });

        this.screen.key(['escape', 'q', 'C-c'], () => {
            this.screen.destroy();
            process.exit(0);
        });

        this.buildLayout();
        this.showDashboard();
        this.screen.render();
    }

    private buildLayout(): void {
        this.headerBox = blessed.box({
            top: 0,
            left: 0,
            right: 0,
            height: 3,
            border: { type: 'line' },
            content: ' {bold}Prompt Guard - TUI{/bold}   {cyan-fg}Local PII & Prompt Injection Scanner{/cyan-fg}',
            tags: true,
            style: { bg: 'blue', fg: 'white' },
        });

        this.navList = blessed.list({
            top: 4,
            left: 0,
            width: 22,
            height: '100%-6',
            border: { type: 'line' },
            tags: true,
            style: {
                fg: 'white',
                bg: 'black',
                selected: { bg: 'blue', fg: 'white' },
            },
            items: [
                ' {bold}Dashboard{/bold}',
                ' {bold}Scan File{/bold}',
                ' {bold}Scan Directory{/bold}',
                ' {bold}View Results{/bold}',
                ' {bold}Sanitized Text{/bold}',
                ' {bold}Configuration{/bold}',
                ' {bold}Export JSON{/bold}',
                ' {bold}About{/bold}',
                ' {bold}Quit{/bold}',
            ],
        });

        this.navList.focus();

        this.mainBox = blessed.box({
            top: 4,
            left: 23,
            right: 0,
            bottom: 1,
            border: { type: 'line' },
            scrollable: true,
            alwaysScroll: true,
            tags: true,
        });

        this.statusBar = blessed.text({
            bottom: 0,
            left: 0,
            right: 0,
            height: 1,
            tags: true,
            style: { fg: 'white', bg: 'black' },
            content: ' {bold}Prompt Guard TUI{/bold}   Navigate: ↑↓/jk   Select: Enter   Back: Tab   Quit: q',
        });

        this.screen.append(this.headerBox);
        this.screen.append(this.navList);
        this.screen.append(this.mainBox);
        this.screen.append(this.statusBar);

        this.navList.on('select', (index: number) => {
            this.handleNavSelect(index);
        });

        this.navList.key(['tab'], () => {
            this.mainBox.focus();
        });
    }

    private handleNavSelect(index: number): void {
        switch (index) {
            case 0:
                this.showDashboard();
                break;
            case 1:
                this.showScanFile();
                break;
            case 2:
                this.showScanDirectory();
                break;
            case 3:
                this.showViewResults();
                break;
            case 4:
                this.showSanitizedText();
                break;
            case 5:
                this.showConfiguration();
                break;
            case 6:
                this.showExportJSON();
                break;
            case 7:
                this.showAbout();
                break;
            case 8:
                this.screen.destroy();
                process.exit(0);
                break;
        }
    }

    private showDashboard(): void {
        const stats = this.currentResult
            ? {
                total: this.currentResult.matches.length,
                critical: this.currentResult.matches.filter((m) => m.severity === 'critical').length,
                high: this.currentResult.matches.filter((m) => m.severity === 'high').length,
                medium: this.currentResult.matches.filter((m) => m.severity === 'medium').length,
                low: this.currentResult.matches.filter((m) => m.severity === 'low').length,
                safe: this.currentResult.isSafe ? 'YES' : 'NO',
            }
            : { total: 0, critical: 0, high: 0, medium: 0, low: 0, safe: 'N/A' };

        const content = `
{bold}Prompt Guard - TUI Dashboard{/bold}
{yellow}─────────────────────────────────────────────{/yellow}

{cyan}Status:{/cyan} ${this.currentResult ? (this.currentResult.isSafe ? '{green}SAFE{/green}' : '{red}UNSAFE{/red}') : '{white}N/A{/white}'} : '{white}${stats.safe}{/white}'
{cyan}File:{/cyan} ${this.currentFile || '(none)'}

{magenta}Scan Statistics:{/magenta}
  {bold}Total Matches:{/bold}  ${stats.total}
  {red}Critical:{/red}   ${stats.critical}
  {red}High:{/red}        ${stats.high}
  {yellow}Medium:{/yellow}   ${stats.medium}
  {green}Low:{/green}       ${stats.low}

{cyan}Ignore List:{/cyan} ${this.ignoreList.length > 0 ? this.ignoreList.join(', ') : '(none)'}
{cyan}Min Severity:{/cyan} ${this.minSeverity || '(none)'}

{yellow}─────────────────────────────────────────────{/yellow}
Select an option from the left menu to begin.
        `;

        this.mainBox.setContent(content);
        this.statusBar.setContent(' {bold}Dashboard{/bold}   Navigate: ↑↓/jk   Select: Enter   Tab: Focus main   Quit: q');
        this.screen.render();
    }

    private showScanFile(): void {
        this.mainBox.setContent(`
{yellow}Scan File{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

Enter a file path to scan for PII and prompt injection patterns.

{green}Usage:{/green} Type the full path to a text file and press Enter.
Examples:
  examples/clean.txt
  examples/leak.txt
  examples/secrets.txt
  /path/to/your/file.txt

{magenta}Input:{/magenta}
        `);

        this.inputBox = blessed.textbox({
            top: 12,
            left: 2,
            width: 50,
            height: 3,
            border: { type: 'line' },
            label: ' File path ',
            inputOnFocus: true,
            style: { fg: 'white', bg: 'black', border: { fg: 'cyan' } },
        });

        this.inputBox.key(['enter'], () => {
            const filePath = this.inputBox!.getValue().trim();
            if (!filePath) {
                this.statusBar.setContent(' {red}Error:{/red} Please enter a file path.');
                this.screen.render();
                return;
            }
            this.inputBox!.destroy();
            this.inputBox = null;
            this.scanFilePath(filePath);
        });

        this.inputBox.key(['escape'], () => {
            this.inputBox!.destroy();
            this.inputBox = null;
            this.showDashboard();
            this.screen.render();
        });

        this.mainBox.append(this.inputBox);
        this.inputBox.focus();
        this.screen.render();
    }

    private showScanDirectory(): void {
        this.mainBox.setContent(`
{yellow}Scan Directory{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

Enter a directory path to recursively scan all text files.

{green}Usage:{/green} Type the full path to a directory and press Enter.
Examples:
  examples/
  src/
  tests/
  /path/to/your/directory

{magenta}Input:{/magenta}
        `);

        this.inputBox = blessed.textbox({
            top: 12,
            left: 2,
            width: 50,
            height: 3,
            border: { type: 'line' },
            label: ' Directory path ',
            inputOnFocus: true,
            style: { fg: 'white', bg: 'black', border: { fg: 'cyan' } },
        });

        this.inputBox.key(['enter'], () => {
            const dirPath = this.inputBox!.getValue().trim();
            if (!dirPath) {
                this.statusBar.setContent(' {red}Error:{/red} Please enter a directory path.');
                this.screen.render();
                return;
            }
            this.inputBox!.destroy();
            this.inputBox = null;
            this.scanDirectoryPath(dirPath);
        });

        this.inputBox.key(['escape'], () => {
            this.inputBox!.destroy();
            this.inputBox = null;
            this.showDashboard();
            this.screen.render();
        });

        this.mainBox.append(this.inputBox);
        this.inputBox.focus();
        this.screen.render();
    }

    private scanFilePath(filePath: string): void {
        try {
            if (!fs.existsSync(filePath)) {
                this.showError(`File not found: ${filePath}`);
                return;
            }
            const content = fs.readFileSync(filePath, 'utf8');
            const result = scanText(content, {
                ignore: this.ignoreList,
                minSeverity: this.minSeverity,
            });
            this.currentFile = filePath;
            this.currentResult = result;
            this.showScanResults(result, filePath);
        } catch (err: any) {
            this.showError(`Error reading file: ${err.message}`);
        }
    }

    private scanDirectoryPath(dirPath: string): void {
        try {
            if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) {
                this.showError(`Not a directory: ${dirPath}`);
                return;
            }
            const results = this.walkAndScan(dirPath);
            this.currentFile = dirPath;
            const allMatches = results.flatMap((r) => r.result.matches);
            const allSafe = results.every((r) => r.result.isSafe);
            const combinedSanitized = results.map((r) => `--- ${r.file} ---\n${r.result.sanitizedText}`).join('\n\n');
            this.currentResult = {
                isSafe: allSafe,
                matches: allMatches,
                sanitizedText: combinedSanitized,
            };
            this.showScanResults(this.currentResult, dirPath);
        } catch (err: any) {
            this.showError(`Error scanning directory: ${err.message}`);
        }
    }

    private walkAndScan(dir: string): Array<{ file: string; result: ScanResult }> {
        const results: Array<{ file: string; result: ScanResult }> = [];
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                results.push(...this.walkAndScan(full));
            } else if (entry.isFile() && this.isTextFile(entry.name)) {
                try {
                    const content = fs.readFileSync(full, 'utf8');
                    const result = scanText(content, {
                        ignore: this.ignoreList,
                        minSeverity: this.minSeverity,
                    });
                    results.push({ file: full, result });
                } catch {
                    // Skip files that can't be read
                }
            }
        }
        return results;
    }

    private isTextFile(filename: string): boolean {
        const textExts = ['.txt', '.ts', '.js', '.json', '.html', '.md', '.yaml', '.yml', '.env', '.csv', '.log'];
        return textExts.includes(path.extname(filename).toLowerCase());
    }

    private showScanResults(result: ScanResult, filePath: string): void {
        const severityColors: Record<Severity, string> = {
            critical: 'red',
            high: 'red',
            medium: 'yellow',
            low: 'green',
        };

        let content = `
{yellow}Scan Results{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

{cyan}File:{/cyan} ${filePath}
{cyan}Status:{/cyan} ${result.isSafe ? '{green}SAFE{/green}' : '{red}UNSAFE{/red}'}
{cyan}Total Matches:{/cyan} ${result.matches.length}

{magenta}Matches:{/magenta}
`;

        if (result.matches.length === 0) {
            content += '{green}No security risks detected.{/green}\n';
        } else {
            result.matches.forEach((m, i) => {
                const color = severityColors[m.severity] || 'white';
                content += `  {${color}-fg}[${i}] ${m.type.toUpperCase()}{/${color}-fg} {white}-${m.severity}-{/white}\n`;
                content += `      {cyan}Value:{/cyan} ${m.value}\n`;
            });
        }

        content += `
{yellow}─────────────────────────────────────────────{/cyan}
{green}Actions:{/green}
  [V] View Sanitized Text
  [E] Export JSON
  [B] Back to Dashboard
`;

        this.mainBox.setContent(content);
        this.statusBar.setContent(' {bold}Results{/bold}   V: View sanitized   E: Export JSON   B: Back   q: Quit');

        this.screen.key(['v'], () => {
            this.showSanitizedText();
        });
        this.screen.key(['e'], () => {
            this.showExportJSON();
        });
        this.screen.key(['b'], () => {
            this.showDashboard();
        });

        this.screen.render();
    }

    private showViewResults(): void {
        if (!this.currentResult) {
            this.showError('No scan results available. Run a scan first.');
            return;
        }

        let content = `
{yellow}Detailed Results{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

{cyan}File:{/cyan} ${this.currentFile || '(unknown)'}
{cyan}Status:{/cyan} ${this.currentResult.isSafe ? '{green}SAFE{/green}' : '{red}UNSAFE{/red}'}
{cyan}Total Matches:{/cyan} ${this.currentResult.matches.length}

{magenta}Match Details:{/magenta}
`;

        if (this.currentResult.matches.length === 0) {
            content += '{green}No security risks detected.{/green}\n';
        } else {
            this.currentResult.matches.forEach((m, i) => {
                content += `  {bold}[${i}]{/bold} {cyan}${m.type}{/cyan} ({m.severity})\n`;
                content += `      Value: ${m.value}\n\n`;
            });
        }

        content += `
Press any key to return to dashboard.
`;

        this.mainBox.setContent(content);
        this.statusBar.setContent(' {bold}View Results{/bold}   Press any key to return   q: Quit');

        this.screen.key(['any'], () => {
            this.showDashboard();
            this.screen.render();
        });

        this.screen.render();
    }

    private showSanitizedText(): void {
        if (!this.currentResult) {
            this.showError('No scan results available. Run a scan first.');
            return;
        }

        this.mainBox.setContent(`
{yellow}Sanitized Text{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

{cyan}File:{/cyan} ${this.currentFile || '(unknown)'}

{white}${this.currentResult.sanitizedText}{/white}

{cyan}─────────────────────────────────────────────{/cyan}
Press any key to return to dashboard.
`);

        this.statusBar.setContent(' {bold}Sanitized Text{/bold}   Press any key to return   q: Quit');

        this.screen.key(['any'], () => {
            this.showDashboard();
            this.screen.render();
        });

        this.screen.render();
    }

    private showConfiguration(): void {
        this.mainBox.setContent(`
{yellow}Configuration{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

{magenta}Ignore List:{/magenta}
Categories to skip during scanning:
${this.ignoreList.length > 0 ? this.ignoreList.map((c) => `  - ${c}`).join('\n') : '  (none)'}

{magenta}Minimum Severity:{/magenta}
${this.minSeverity || '  (none - scan all)'}

{green}Actions:{/green}
  [I] Edit ignore list
  [S] Set minimum severity
  [R] Reset to defaults
  [B] Back to dashboard
`);

        this.statusBar.setContent(' {bold}Configuration{/bold}   I: Ignore list   S: Severity   R: Reset   B: Back   q: Quit');

        this.screen.key(['i'], () => {
            this.editIgnoreList();
        });
        this.screen.key(['s'], () => {
            this.setMinSeverity();
        });
        this.screen.key(['r'], () => {
            this.ignoreList = [];
            this.minSeverity = undefined;
            this.statusBar.setContent(' {green}Configuration reset to defaults.{/green}');
            this.screen.render();
            setTimeout(() => this.showConfiguration(), 1000);
        });
        this.screen.key(['b'], () => {
            this.showDashboard();
        });

        this.screen.render();
    }

    private editIgnoreList(): void {
        const categories = Object.keys(PII_PATTERNS).concat(['prompt_injection']);
        this.mainBox.setContent(`
{yellow}Edit Ignore List{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

Select categories to ignore (toggle):
${categories.map((c) => `  [${this.ignoreList.includes(c) ? '{green}x{/green}' : ' '}] ${c}`).join('\n')}

{cyan}Input:{/cyan} Type a category name to toggle, or press Enter when done.
`);

        this.inputBox = blessed.textbox({
            top: 15,
            left: 2,
            width: 40,
            height: 3,
            border: { type: 'line' },
            label: ' Category name ',
            inputOnFocus: true,
            style: { fg: 'white', bg: 'black', border: { fg: 'cyan' } },
        });

        this.inputBox.key(['enter'], () => {
            const cat = this.inputBox!.getValue().trim();
            if (cat) {
                const idx = this.ignoreList.indexOf(cat);
                if (idx >= 0) {
                    this.ignoreList.splice(idx, 1);
                } else {
                    this.ignoreList.push(cat);
                }
            }
            this.inputBox!.destroy();
            this.inputBox = null;
            this.showConfiguration();
        });

        this.inputBox.key(['escape'], () => {
            this.inputBox!.destroy();
            this.inputBox = null;
            this.showConfiguration();
        });

        this.mainBox.append(this.inputBox);
        this.inputBox.focus();
        this.screen.render();
    }

    private setMinSeverity(): void {
        this.mainBox.setContent(`
{yellow}Set Minimum Severity{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

Current: ${this.minSeverity || '(none)'}

Select minimum severity level:
  [1] low      (scan everything)
  [2] medium   (skip low)
  [3] high     (skip low and medium)
  [4] critical (skip low, medium, high)
  [5] none     (scan everything)

{cyan}Input:{/cyan} Type 1-5 to select.
`);

        this.inputBox = blessed.textbox({
            top: 14,
            left: 2,
            width: 10,
            height: 3,
            border: { type: 'line' },
            label: ' Level ',
            inputOnFocus: true,
            style: { fg: 'white', bg: 'black', border: { fg: 'cyan' } },
        });

        this.inputBox.key(['enter'], () => {
            const val = this.inputBox!.getValue().trim();
            const map: Record<string, Severity | undefined> = {
                '1': 'low',
                '2': 'medium',
                '3': 'high',
                '4': 'critical',
                '5': undefined,
            };
            this.minSeverity = map[val] ?? this.minSeverity;
            this.inputBox!.destroy();
            this.inputBox = null;
            this.showConfiguration();
        });

        this.inputBox.key(['escape'], () => {
            this.inputBox!.destroy();
            this.inputBox = null;
            this.showConfiguration();
        });

        this.mainBox.append(this.inputBox);
        this.inputBox.focus();
        this.screen.render();
    }

    private showExportJSON(): void {
        if (!this.currentResult) {
            this.showError('No scan results available. Run a scan first.');
            return;
        }

        const output = JSON.stringify({
            file: this.currentFile,
            isSafe: this.currentResult.isSafe,
            matches: this.currentResult.matches,
            sanitizedText: this.currentResult.sanitizedText,
        }, null, 2);

        this.mainBox.setContent(`
{yellow}Export JSON{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

{white}${output}{/white}

{cyan}─────────────────────────────────────────────{/cyan}
Press any key to return to dashboard.
`);

        this.statusBar.setContent(' {bold}Export JSON{/bold}   Press any key to return   q: Quit');

        this.screen.key(['any'], () => {
            this.showDashboard();
            this.screen.render();
        });

        this.screen.render();
    }

    private showAbout(): void {
        this.mainBox.setContent(`
{yellow}About Prompt Guard{/yellow}
{cyan}─────────────────────────────────────────────{/cyan}

{bold}Prompt Guard TUI{/bold}
A lightweight terminal UI for scanning prompts for PII and prompt injection.

{magenta}Features:{/magenta}
  - Local pattern-based scanning (no network calls)
  - PII detection: email, credit cards, API keys, SSN, phone, IP, social handles
  - Secret detection: GitHub tokens, AWS keys, DB URLs, JWTs, Stripe keys, SSH keys
  - Prompt injection detection
  - Severity levels: low, medium, high, critical
  - JSON export
  - Sanitized text preview

{magenta}Version:{/magenta} 2.0.0
{magenta}License:{/magenta} MIT
{magenta}Repository:{/magenta} https://github.com/PyMite6941/prompt-guard

Press any key to return to dashboard.
`);

        this.statusBar.setContent(' {bold}About{/bold}   Press any key to return   q: Quit');

        this.screen.key(['any'], () => {
            this.showDashboard();
            this.screen.render();
        });

        this.screen.render();
    }

    private showError(message: string): void {
        this.mainBox.setContent(`
{red}Error{/red}
{cyan}─────────────────────────────────────────────{/cyan}

{red}${message}{/red}

Press any key to return to dashboard.
`);

        this.statusBar.setContent(' {red}Error{/red}   Press any key to return   q: Quit');

        this.screen.key(['any'], () => {
            this.showDashboard();
            this.screen.render();
        });

        this.screen.render();
    }
}

function main(): void {
    const args = process.argv.slice(2);
    const tuiFlag = args.includes('--tui') || args.includes('-t');

    if (tuiFlag) {
        new PromptGuardTUI();
    } else {
        console.error('Error: Use --tui flag to launch the TUI.');
        console.error('Usage: prompt-guard --tui');
        process.exit(1);
    }
}

main();
