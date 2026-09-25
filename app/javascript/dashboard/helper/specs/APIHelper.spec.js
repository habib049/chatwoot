import createAxios from '../APIHelper';
import { recoverSession } from '../ssoSession';

vi.mock('../ssoSession', () => ({
  recoverSession: vi.fn(() => Promise.resolve()),
}));

const buildInterceptor = () => {
  let onError;
  const instance = {
    defaults: { headers: { common: {} } },
    interceptors: {
      response: {
        use: (_ok, err) => {
          onError = err;
        },
      },
    },
  };
  createAxios({ create: () => instance });
  return onError;
};

const errorWith = data => ({ response: { status: 401, data } });

describe('APIHelper response interceptor', () => {
  afterEach(() => {
    delete window.chatwootConfig;
    recoverSession.mockClear();
  });

  it.each(['sso_identity_changed', 'sso_session_required'])(
    'calls recoverSession for %s in SSO mode and rethrows',
    async code => {
      window.chatwootConfig = { ssoMode: true };
      const error = errorWith({ error_code: code });

      await expect(buildInterceptor()(error)).rejects.toBe(error);
      expect(recoverSession).toHaveBeenCalledTimes(1);
    }
  );

  it('ignores other 401 responses, such as a Pundit-style error', async () => {
    window.chatwootConfig = { ssoMode: true };
    const error = errorWith({ error_code: 'not_authorized' });

    await expect(buildInterceptor()(error)).rejects.toBe(error);
    expect(recoverSession).not.toHaveBeenCalled();
  });

  it.each([
    ['null', null],
    ['a string', 'sso_identity_changed'],
    ['an array', ['sso_identity_changed']],
    ['a number', 5],
    ['missing', undefined],
    ['a non-string error_code', { error_code: ['sso_identity_changed'] }],
    ['no error_code', { message: 'x' }],
  ])(
    'ignores a response whose data is %s without throwing',
    async (_, data) => {
      window.chatwootConfig = { ssoMode: true };
      const error = errorWith(data);

      await expect(buildInterceptor()(error)).rejects.toBe(error);
      expect(recoverSession).not.toHaveBeenCalled();
    }
  );

  it('ignores an error with no response at all', async () => {
    window.chatwootConfig = { ssoMode: true };
    const error = new Error('Network Error');

    await expect(buildInterceptor()(error)).rejects.toBe(error);
    expect(recoverSession).not.toHaveBeenCalled();
  });

  it('never calls recoverSession when SSO mode is off', async () => {
    window.chatwootConfig = { ssoMode: false };
    const error = errorWith({ error_code: 'sso_identity_changed' });

    await expect(buildInterceptor()(error)).rejects.toBe(error);
    expect(recoverSession).not.toHaveBeenCalled();
  });

  it('still rethrows the original error when the recovery loop guard rejects', async () => {
    window.chatwootConfig = { ssoMode: true };
    recoverSession.mockRejectedValueOnce(new Error('sso_recovery_loop'));
    const error = errorWith({ error_code: 'sso_session_required' });

    await expect(buildInterceptor()(error)).rejects.toBe(error);
  });
});
