/// <reference types="vite/client" />

/**
 * Build-time configuration. Everything here is embedded in the client bundle
 * and is therefore public - never put a secret in a `VITE_` variable.
 */
interface ImportMetaEnv {
  /** Base URL of the PassM API, including the version prefix. */
  readonly VITE_API_URL?: string;
  readonly VITE_APP_NAME?: string;
  /** Shown in the header; distinguishes staging from production. */
  readonly VITE_ENVIRONMENT_LABEL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
