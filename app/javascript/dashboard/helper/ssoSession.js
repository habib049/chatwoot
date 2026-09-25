/* global axios */
import authAPI from 'dashboard/api/auth';
import {
  setAuthCredentials,
  clearBrowserSessionCookies,
  clearLocalStorageOnLogout,
  clearSessionStorageOnLogout,
} from 'dashboard/store/utils/api';
import SessionStorage from 'shared/helpers/sessionStorage';
import { SESSION_STORAGE_KEYS } from 'dashboard/constants/sessionStorage';

export const RECOVERY_WINDOW_MS = 30 * 1000;

// Logs in from the proxy identity and stores the session like a normal login. Rejects with an Error
// whose message and `errorCode` are the server error_code (or 'sso_login_failed').
export const proxyLogin = async () => {
  try {
    const response = await authAPI.proxyLogin();
    setAuthCredentials(response);
    // The shared axios instance was built before this session existed; give it the new headers.
    const common = axios?.defaults?.headers?.common;
    if (common) {
      ['access-token', 'token-type', 'client', 'expiry', 'uid'].forEach(key => {
        common[key] = response.headers[key];
      });
    }
    return response.data.data;
  } catch (error) {
    const code = error?.response?.data?.error_code;
    const errorCode = typeof code === 'string' ? code : 'sso_login_failed';
    throw Object.assign(new Error(errorCode), { errorCode });
  }
};

// Clears the app session without redirecting and reloads once so the SPA proxy-logs-in again.
// The guard is an SPA-local timestamp: a second call inside the window rejects instead of looping.
export const recoverSession = () => {
  const now = Date.now();
  const last = SessionStorage.get(SESSION_STORAGE_KEYS.SSO_RECOVER_AT);
  const elapsed = now - Number(last);
  if (last !== null && elapsed >= 0 && elapsed < RECOVERY_WINDOW_MS) {
    return Promise.reject(new Error('sso_recovery_loop'));
  }
  clearBrowserSessionCookies();
  clearLocalStorageOnLogout();
  clearSessionStorageOnLogout();
  SessionStorage.set(SESSION_STORAGE_KEYS.SSO_RECOVER_AT, now);
  window.location.reload();
  return Promise.resolve();
};
