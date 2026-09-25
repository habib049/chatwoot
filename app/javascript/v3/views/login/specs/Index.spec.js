import { mount, flushPromises } from '@vue/test-utils';
import { createStore } from 'vuex';
import Login from '../Index.vue';
import { login } from '../../../api/auth';
import { proxyLogin } from 'dashboard/helper/ssoSession';

vi.mock('../../../api/auth', () => ({ login: vi.fn() }));
vi.mock('dashboard/helper/ssoSession', () => ({ proxyLogin: vi.fn() }));
vi.mock('dashboard/composables', () => ({ useAlert: vi.fn() }));

const mountLogin = (props = {}) => {
  const store = createStore({
    getters: { 'globalConfig/get': () => ({ installationName: 'Chatwoot' }) },
  });
  return mount(Login, {
    props,
    global: {
      plugins: [store],
      mocks: {
        $t: key => key,
        $route: { query: {} },
        $router: { replace: vi.fn() },
      },
      stubs: {
        RouterLink: { template: '<a><slot /></a>' },
        GoogleOAuthButton: { template: '<div data-test="google" />' },
        Spinner: { template: '<div data-test="spinner" />' },
        NextButton: {
          props: ['label'],
          emits: ['click'],
          template:
            '<button data-test="button" @click="$emit(\'click\')">{{ label }}</button>',
        },
        Icon: true,
        MfaVerification: true,
        SessionLimitOverlay: true,
      },
    },
  });
};

describe('login view', () => {
  const originalLocation = window.location;

  beforeEach(() => {
    login.mockReset();
    login.mockResolvedValue({});
    proxyLogin.mockReset();
    Object.defineProperty(window, 'location', {
      value: { href: '/app/login', search: '' },
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    delete window.chatwootConfig;
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
  });

  describe('in SSO mode', () => {
    beforeEach(() => {
      window.chatwootConfig = {
        ssoMode: true,
        allowedLoginMethods: ['email', 'google_oauth', 'saml'],
        googleOAuthClientId: 'id',
        signupEnabled: 'true',
      };
    });

    it('ignores the sso_auth_token and email query params and never posts sign_in', async () => {
      proxyLogin.mockResolvedValue({ id: 1, accounts: [] });
      mountLogin({ ssoAuthToken: 'tok', email: 'a%40b.com' });
      await flushPromises();

      expect(login).not.toHaveBeenCalled();
      expect(proxyLogin).toHaveBeenCalledTimes(1);
    });

    it('renders no form, Google or SAML button, reset link or signup link', async () => {
      proxyLogin.mockReturnValue(new Promise(() => {}));
      const wrapper = mountLogin();
      await flushPromises();

      expect(wrapper.find('form').exists()).toBe(false);
      expect(wrapper.find('[data-testid="email_input"]').exists()).toBe(false);
      expect(wrapper.find('[data-test="google"]').exists()).toBe(false);
      expect(wrapper.html()).not.toContain('/app/login/sso');
      expect(wrapper.html()).not.toContain('auth/reset/password');
      expect(wrapper.html()).not.toContain('auth/signup');
      expect(wrapper.find('[data-test="spinner"]').exists()).toBe(true);
    });

    it('calls proxyLogin once and redirects with getLoginRedirectURL on success', async () => {
      proxyLogin.mockResolvedValue({ id: 1, accounts: [{ id: 7 }] });
      mountLogin({ ssoAccountId: '7' });
      await flushPromises();

      expect(proxyLogin).toHaveBeenCalledTimes(1);
      expect(window.location).toBe('/app/accounts/7/dashboard');
    });

    it('shows the error code and a Retry button without redirecting or retrying', async () => {
      proxyLogin.mockRejectedValue(
        Object.assign(new Error('sso_user_inactive'), {
          errorCode: 'sso_user_inactive',
        })
      );
      const wrapper = mountLogin();
      await flushPromises();

      expect(wrapper.find('[data-testid="sso_error_code"]').text()).toBe(
        'sso_user_inactive'
      );
      expect(wrapper.find('[data-testid="sso_retry"]').exists()).toBe(true);
      expect(proxyLogin).toHaveBeenCalledTimes(1);
      expect(window.location.href).toBe('/app/login');
    });

    it('retries only when the Retry button is clicked', async () => {
      proxyLogin.mockRejectedValueOnce(
        Object.assign(new Error('x'), { errorCode: 'sso_identity_missing' })
      );
      proxyLogin.mockResolvedValueOnce({ id: 1, accounts: [{ id: 2 }] });
      const wrapper = mountLogin();
      await flushPromises();

      await wrapper.find('[data-testid="sso_retry"]').trigger('click');
      await flushPromises();

      expect(proxyLogin).toHaveBeenCalledTimes(2);
      expect(window.location).toBe('/app/accounts/2/dashboard');
    });

    it('shows a generic error state when the rejection has no string error_code', async () => {
      proxyLogin.mockRejectedValue({ errorCode: ['nope'] });
      const wrapper = mountLogin();
      await flushPromises();

      expect(wrapper.find('[data-testid="sso_error_code"]').text()).toBe(
        'sso_login_failed'
      );
    });
  });

  describe('with SSO mode off', () => {
    beforeEach(() => {
      window.chatwootConfig = {
        ssoMode: false,
        allowedLoginMethods: ['email'],
        signupEnabled: 'false',
      };
    });

    it('renders the form and never calls proxyLogin', async () => {
      const wrapper = mountLogin();
      await flushPromises();

      expect(wrapper.find('form').exists()).toBe(true);
      expect(proxyLogin).not.toHaveBeenCalled();
    });

    it('auto-submits when ssoAuthToken is present', async () => {
      mountLogin({ ssoAuthToken: 'tok', email: 'a%40b.com' });
      await flushPromises();

      expect(login).toHaveBeenCalledTimes(1);
      expect(login.mock.calls[0][0]).toMatchObject({
        sso_auth_token: 'tok',
        email: 'a@b.com',
      });
    });
  });
});
