export { scanText } from './scanner';
export { callAIGuarded } from './ai';
export { evaluateHookInput } from './hook';
export type { HookOptions, HookResult } from './hook';
export { createVaultCatalogTool, getDefaultVaultPath, SecretVault } from './vault';
export { launchVaultPopup } from './vault-popup';
export type { VaultPopupOptions } from './vault-popup';
export type { SafePromptOptions } from './ai';
export type {
    SecretVaultOptions,
    SecretMeta,
    AgentSecretInfo,
    CapturedPrompt,
    AgentCatalogTool,
} from './vault';
export type { Severity, ScanMatch, ScanResult, ScanOptions } from './scanner';
export { scanModelResponse } from './ai';
export {
	generateHtmlReport,
	generateJunitXml,
	appendAuditLog,
	readAuditLog,
} from './report';
export type { ReportFile, ReportOptions, AuditLogEntry } from './report';
