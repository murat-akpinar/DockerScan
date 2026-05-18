/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
  readonly DEV: boolean;
  // Add other env variables as needed
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

