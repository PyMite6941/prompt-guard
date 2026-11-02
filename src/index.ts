export { scanText } from './scanner';
export { callAIGuarded } from './ai';
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
