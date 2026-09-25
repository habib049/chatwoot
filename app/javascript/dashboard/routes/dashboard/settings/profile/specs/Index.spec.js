import { mount } from '@vue/test-utils';
import { createStore } from 'vuex';
import Index from '../Index.vue';

const passThrough = { template: '<div><slot /></div>' };

const mountProfile = ({ ssoMode, disableUserProfileUpdate = false }) => {
  window.chatwootConfig = { ssoMode, isMfaEnabled: 'true' };
  const store = createStore({
    getters: {
      getCurrentUser: () => ({
        name: 'Agent',
        email: 'agent@example.com',
        accounts: [],
      }),
      getCurrentUserID: () => 1,
      getUISettings: () => ({}),
      'globalConfig/get': () => ({ disableUserProfileUpdate }),
      'globalConfig/isOnChatwootCloud': () => false,
    },
  });
  return mount(Index, {
    global: {
      plugins: [store],
      mocks: { $t: key => key },
      stubs: {
        SectionLayout: passThrough,
        BaseSettingsHeader: true,
        UserProfilePicture: true,
        UserBasicDetails: {
          name: 'UserBasicDetails',
          props: ['emailEnabled'],
          template: '<div />',
        },
        FontSize: true,
        UserLanguageSelect: true,
        MessageSignature: true,
        RadioCard: true,
        ChangePassword: { template: '<div data-test="change-password" />' },
        MfaSettingsCard: { template: '<div data-test="mfa" />' },
        ActiveSessions: true,
        Policy: true,
        AccessToken: true,
      },
    },
  });
};

describe('profile Index.vue', () => {
  afterEach(() => {
    delete window.chatwootConfig;
  });

  it('hides ChangePassword, MFA and email editing in SSO mode', () => {
    const wrapper = mountProfile({ ssoMode: true });

    expect(wrapper.find('[data-test="change-password"]').exists()).toBe(false);
    expect(wrapper.find('[data-test="mfa"]').exists()).toBe(false);
    expect(
      wrapper.findComponent({ name: 'UserBasicDetails' }).props('emailEnabled')
    ).toBe(false);
  });

  it('keeps ChangePassword, MFA and an editable email when SSO is off', () => {
    const wrapper = mountProfile({ ssoMode: false });

    expect(wrapper.find('[data-test="change-password"]').exists()).toBe(true);
    expect(wrapper.find('[data-test="mfa"]').exists()).toBe(true);
    expect(
      wrapper.findComponent({ name: 'UserBasicDetails' }).props('emailEnabled')
    ).toBe(true);
  });

  it('keeps the existing disableUserProfileUpdate behaviour when SSO is off', () => {
    const wrapper = mountProfile({
      ssoMode: false,
      disableUserProfileUpdate: true,
    });

    expect(wrapper.find('[data-test="change-password"]').exists()).toBe(false);
    expect(wrapper.find('[data-test="mfa"]').exists()).toBe(true);
    expect(
      wrapper.findComponent({ name: 'UserBasicDetails' }).props('emailEnabled')
    ).toBe(false);
  });

  it('treats the string "true" as SSO off', () => {
    const wrapper = mountProfile({ ssoMode: 'true' });

    expect(wrapper.find('[data-test="change-password"]').exists()).toBe(true);
  });
});
