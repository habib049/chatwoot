import Cookies from 'js-cookie';
import authAPI from 'dashboard/api/auth';
import * as APIHelpers from 'dashboard/store/utils/api';
import SessionStorage from 'shared/helpers/sessionStorage';
import { SESSION_STORAGE_KEYS } from 'dashboard/constants/sessionStorage';
import { proxyLogin, recoverSession, RECOVERY_WINDOW_MS } from '../ssoSession';

vi.mock('dashboard/api/auth', () => ({ default: { proxyLogin: vi.fn() } }));

const KEY = SESSION_STORAGE_KEYS.SSO_RECOVER_AT;

describe('ssoSession', () => {
  const originalLocation = window.location;
  const reload = vi.fn();

  beforeEach(() => {
    reload.mockClear();
    Object.defineProperty(window, 'location', {
      value: { reload },
      writable: true,
      configurable: true,
    });
    window.sessionStorage.clear();
    window.axios = { defaults: { headers: { common: {} } } };
    Cookies.set('cw_d_session_info', '{}');
    Cookies.set('auth_data', 'x');
    Cookies.set('user', 'y');
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
    delete window.axios;
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  describe('proxyLogin', () => {
    it('stores credentials via setAuthCredentials and returns the user', async () => {
      const setAuth = vi
        .spyOn(APIHelpers, 'setAuthCredentials')
        .mockImplementation(() => {});
      const response = {
        headers: { 'access-token': 't', client: 'c', uid: 'u', expiry: '1' },
        data: { data: { id: 1, name: 'Alice' } },
      };
      authAPI.proxyLogin.mockResolvedValue(response);

      await expect(proxyLogin()).resolves.toEqual({ id: 1, name: 'Alice' });

      expect(setAuth).toHaveBeenCalledWith(response);
      expect(window.axios.defaults.headers.common['access-token']).toBe('t');
      expect(window.axios.defaults.headers.common.client).toBe('c');
    });

    it('surfaces the server error_code when rejected', async () => {
      authAPI.proxyLogin.mockRejectedValue({
        response: { data: { error_code: 'sso_user_inactive' } },
      });

      await expect(proxyLogin()).rejects.toMatchObject({
        message: 'sso_user_inactive',
        errorCode: 'sso_user_inactive',
      });
    });

    it('falls back to a generic code when there is no string error_code', async () => {
      authAPI.proxyLogin.mockRejectedValue({ response: { data: null } });
      await expect(proxyLogin()).rejects.toMatchObject({
        errorCode: 'sso_login_failed',
      });

      authAPI.proxyLogin.mockRejectedValue(new Error('Network Error'));
      await expect(proxyLogin()).rejects.toMatchObject({
        errorCode: 'sso_login_failed',
      });
    });
  });

  describe('recoverSession', () => {
    it('clears the auth cookies, stamps the time and reloads without redirecting', async () => {
      await recoverSession();

      expect(Cookies.get('cw_d_session_info')).toBeUndefined();
      expect(Cookies.get('auth_data')).toBeUndefined();
      expect(Cookies.get('user')).toBeUndefined();
      expect(typeof SessionStorage.get(KEY)).toBe('number');
      expect(reload).toHaveBeenCalledTimes(1);
      expect(window.location.href).toBeUndefined();
    });

    it('reloads at most once per 30 seconds and then rejects', async () => {
      await recoverSession();
      await expect(recoverSession()).rejects.toThrow('sso_recovery_loop');

      expect(reload).toHaveBeenCalledTimes(1);
    });

    it('reloads again once the window has passed', async () => {
      vi.useFakeTimers();
      await recoverSession();
      vi.advanceTimersByTime(RECOVERY_WINDOW_MS + 1);
      await recoverSession();

      expect(reload).toHaveBeenCalledTimes(2);
    });

    it('ignores a garbage or future timestamp instead of blocking forever', async () => {
      window.sessionStorage.setItem(KEY, 'abc');
      await recoverSession();
      window.sessionStorage.setItem(KEY, String(Date.now() + 10 * 60 * 1000));
      await recoverSession();

      expect(reload).toHaveBeenCalledTimes(2);
    });
  });
});
