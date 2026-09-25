import Cookies from 'js-cookie';
import authAPI from 'dashboard/api/auth';
import {
  clearCookiesOnLogout,
  getLoadingStatus,
  parseAPIErrorResponse,
  setLoadingStatus,
  throwErrorMessage,
  parseLinearAPIErrorResponse,
} from '../api';

describe('#getLoadingStatus', () => {
  it('returns correct status', () => {
    expect(getLoadingStatus({ fetchAPIloadingStatus: true })).toBe(true);
  });
});

describe('#setLoadingStatus', () => {
  it('set correct status', () => {
    const state = { fetchAPIloadingStatus: true };
    setLoadingStatus(state, false);
    expect(state.fetchAPIloadingStatus).toBe(false);
  });
});

describe('#parseAPIErrorResponse', () => {
  it('returns correct values', () => {
    expect(
      parseAPIErrorResponse({
        response: { data: { message: 'Error Message [message]' } },
      })
    ).toBe('Error Message [message]');

    expect(
      parseAPIErrorResponse({
        response: { data: { error: 'Error Message [error]' } },
      })
    ).toBe('Error Message [error]');

    expect(parseAPIErrorResponse('Error: 422 Failed')).toBe(
      'Error: 422 Failed'
    );
  });
});

describe('#throwErrorMessage', () => {
  it('throws correct error', () => {
    const errorFn = function throwErrorMessageFn() {
      throwErrorMessage({
        response: { data: { message: 'Error Message [message]' } },
      });
    };
    expect(errorFn).toThrow('Error Message [message]');
  });
});

describe('#parseLinearAPIErrorResponse', () => {
  it('returns correct values', () => {
    expect(
      parseLinearAPIErrorResponse(
        {
          response: {
            data: {
              error: {
                errors: [
                  {
                    message: 'Error Message [message]',
                  },
                ],
              },
            },
          },
        },
        'Default Message'
      )
    ).toBe('Error Message [message]');
  });
});

describe('#clearCookiesOnLogout', () => {
  const originalLocation = window.location;
  const setLocation = href => {
    const url = new URL(href);
    Object.defineProperty(window, 'location', {
      value: {
        href: url.href,
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port,
      },
      writable: true,
      configurable: true,
    });
  };

  beforeEach(() => {
    Cookies.set('cw_d_session_info', '{}');
    Cookies.set('auth_data', 'x');
    Cookies.set('user', 'y');
    setLocation('https://chat.example.com/app/accounts/1/dashboard');
  });

  afterEach(() => {
    delete window.chatwootConfig;
    delete window.globalConfig;
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
  });

  const expectSessionCleared = () => {
    expect(Cookies.get('cw_d_session_info')).toBeUndefined();
    expect(Cookies.get('auth_data')).toBeUndefined();
    expect(Cookies.get('user')).toBeUndefined();
  };

  it('redirects to the portal host in SSO mode after clearing the session', () => {
    window.chatwootConfig = { ssoMode: true, smbName: 'portal' };
    window.globalConfig = { LOGOUT_REDIRECT_LINK: 'https://elsewhere.test' };

    clearCookiesOnLogout();

    expectSessionCleared();
    expect(window.location).toBe('https://portal.example.com/');
  });

  it('throws in SSO mode when smbName is missing and does not redirect', () => {
    window.chatwootConfig = { ssoMode: true, smbName: '' };

    expect(() => clearCookiesOnLogout()).toThrow('SMB_NAME is required');
    expect(window.location.href).toBe(
      'https://chat.example.com/app/accounts/1/dashboard'
    );
  });

  it('never touches the _oauth2_proxy cookie', () => {
    Cookies.set('_oauth2_proxy', 'keep');
    window.chatwootConfig = { ssoMode: true, smbName: 'portal' };

    clearCookiesOnLogout();

    expect(Cookies.get('_oauth2_proxy')).toBe('keep');
    Cookies.remove('_oauth2_proxy');
  });

  it('redirects to LOGOUT_REDIRECT_LINK when SSO is off', () => {
    window.chatwootConfig = { ssoMode: false, smbName: 'portal' };
    window.globalConfig = { LOGOUT_REDIRECT_LINK: 'https://elsewhere.test' };

    clearCookiesOnLogout();

    expectSessionCleared();
    expect(window.location).toBe('https://elsewhere.test');
  });

  it('redirects to / when SSO is off and no LOGOUT_REDIRECT_LINK is set', () => {
    clearCookiesOnLogout();

    expect(window.location).toBe('/');
  });
});

describe('authAPI#logout', () => {
  const originalLocation = window.location;

  beforeEach(() => {
    Cookies.set('cw_d_session_info', '{}');
    Object.defineProperty(window, 'location', {
      value: {
        href: 'https://chat.example.com/',
        protocol: 'https:',
        hostname: 'chat.example.com',
        port: '',
      },
      writable: true,
      configurable: true,
    });
    window.axios = { delete: vi.fn() };
  });

  afterEach(() => {
    delete window.chatwootConfig;
    delete window.globalConfig;
    delete window.axios;
    Cookies.remove('cw_d_session_info');
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
  });

  it('clears the session and redirects even when sign_out returns 401 in SSO mode', async () => {
    window.chatwootConfig = { ssoMode: true, smbName: 'portal' };
    window.axios.delete.mockRejectedValue({
      response: { status: 401, data: { error_code: 'sso_identity_changed' } },
    });

    await authAPI.logout();

    expect(window.axios.delete).toHaveBeenCalledTimes(1);
    expect(Cookies.get('cw_d_session_info')).toBeUndefined();
    expect(window.location).toBe('https://portal.example.com/');
  });

  it('sends only the app sign_out request and never an oauth2-proxy sign-out', async () => {
    window.chatwootConfig = { ssoMode: true, smbName: 'portal' };
    window.axios.delete.mockResolvedValue({ data: {} });

    await authAPI.logout();

    expect(window.axios.delete).toHaveBeenCalledTimes(1);
    const [url] = window.axios.delete.mock.calls[0];
    expect(url).toBe('auth/sign_out');
    expect(JSON.stringify(window.axios.delete.mock.calls)).not.toMatch(
      /oauth2/
    );
  });

  it('rejects when smbName is missing in SSO mode even if sign_out succeeded', async () => {
    window.chatwootConfig = { ssoMode: true, smbName: '' };
    window.axios.delete.mockResolvedValue({ data: {} });

    await expect(authAPI.logout()).rejects.toThrow('SMB_NAME is required');
  });

  it('does not clear cookies when sign_out fails and SSO is off', async () => {
    window.chatwootConfig = { ssoMode: false };
    const error = { response: { status: 401 } };
    window.axios.delete.mockRejectedValue(error);

    await expect(authAPI.logout()).rejects.toBe(error);
    expect(Cookies.get('cw_d_session_info')).toBe('{}');
    expect(window.location.href).toBe('https://chat.example.com/');
  });

  it('clears the session and redirects to / when sign_out succeeds and SSO is off', async () => {
    window.chatwootConfig = { ssoMode: false };
    window.axios.delete.mockResolvedValue({ data: {} });

    await authAPI.logout();

    expect(Cookies.get('cw_d_session_info')).toBeUndefined();
    expect(window.location).toBe('/');
  });
});
