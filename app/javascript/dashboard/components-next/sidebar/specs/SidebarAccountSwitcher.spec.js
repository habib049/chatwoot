import { mount } from '@vue/test-utils';
import { ref } from 'vue';
import SidebarAccountSwitcher from '../SidebarAccountSwitcher.vue';

const getters = {
  getCurrentUser: {
    accounts: [
      { id: 1, name: 'A', role: 'agent' },
      { id: 2, name: 'B', role: 'agent' },
    ],
  },
  getUserAccounts: [
    { id: 1, name: 'A' },
    { id: 2, name: 'B' },
  ],
  'globalConfig/get': { createNewAccountFromDashboard: true },
};

vi.mock('dashboard/composables/store', () => ({
  useMapGetter: key => ref(getters[key]),
}));

vi.mock('dashboard/composables/useAccount', () => ({
  useAccount: () => ({
    accountId: ref(1),
    currentAccount: ref({ name: 'A' }),
  }),
}));

const slotPassThrough = { template: '<div><slot /></div>' };

const mountSwitcher = ssoMode => {
  window.chatwootConfig = { ssoMode };
  return mount(SidebarAccountSwitcher, {
    global: {
      stubs: {
        DropdownContainer: {
          template: '<div><slot name="default" :close="() => {}" /></div>',
        },
        DropdownBody: slotPassThrough,
        DropdownSection: slotPassThrough,
        DropdownItem: slotPassThrough,
        ButtonNext: {
          template: '<button data-test="create-account"><slot /></button>',
        },
        Icon: true,
        Logo: true,
      },
    },
  });
};

describe('SidebarAccountSwitcher.vue', () => {
  afterEach(() => {
    delete window.chatwootConfig;
  });

  it('hides create-account in SSO mode', () => {
    const wrapper = mountSwitcher(true);

    expect(wrapper.find('[data-test="create-account"]').exists()).toBe(false);
  });

  it('shows create-account when SSO is off', () => {
    const wrapper = mountSwitcher(false);

    expect(wrapper.find('[data-test="create-account"]').exists()).toBe(true);
  });

  it('shows create-account when the SSO flag is the string "true"', () => {
    const wrapper = mountSwitcher('true');

    expect(wrapper.find('[data-test="create-account"]').exists()).toBe(true);
  });
});
