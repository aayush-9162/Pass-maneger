/**
 * API client for the PassVault backend.
 *
 * All vault data sent through this module is PRE-ENCRYPTED by crypto.js.
 * The server stores and returns opaque ciphertext — it never decrypts.
 *
 * Field-name mapping:
 *  - crypto.js outputs camelCase: { encryptedData, iv }
 *  - Server expects snake_case:   { encrypted_data, iv }
 *  - This module handles the translation in saveVaultEntry()
 */

import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000/api',
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
});

// ── Request interceptor: attach JWT to every request ───────────────────────
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ── Response interceptor: auto-logout on 401 ──────────────────────────────
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      sessionStorage.removeItem('token');
      sessionStorage.removeItem('salt');
      sessionStorage.removeItem('keyVerifier');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// ── Auth endpoints ─────────────────────────────────────────────────────────

export const register = (email, password) =>
  api.post('/auth/register', { email, password });

export const login = (email, password) =>
  api.post('/auth/login', { email, password });

// ── Vault endpoints (blind encrypted storage) ──────────────────────────────

/**
 * Sends an encrypted vault entry to the server for storage.
 * Maps camelCase (from crypto.js) → snake_case (server schema).
 *
 * @param {string} encryptedData — Base64-encoded AES-GCM ciphertext
 * @param {string} iv — Base64-encoded 96-bit initialization vector
 */
export const saveVaultEntry = (encryptedData, iv) =>
  api.post('/vault', { encrypted_data: encryptedData, iv });

/** Retrieves all encrypted entries for the authenticated user. */
export const getVaultEntries = () =>
  api.get('/vault');

/** Deletes a vault entry by ID. Server validates ownership via JWT. */
export const deleteVaultEntry = (id) =>
  api.delete(`/vault/${id}`);

export default api;
