import fs from 'fs';
import path from 'path';

const dashboard = path.resolve(__dirname, '../../../../../..');
const files = [
  'dashboard/routes/dashboard/settings/profile/Index.vue',
  'dashboard/components-next/sidebar/SidebarAccountSwitcher.vue',
];

describe('SSO gated components', () => {
  it.each(files)('%s only uses the isSsoMode() predicate', file => {
    const source = fs.readFileSync(path.join(dashboard, file), 'utf8');

    expect(source).toContain("from 'shared/helpers/ssoMode'");
    expect(source).toMatch(/isSsoMode\(\)/);
    expect(source).not.toMatch(/chatwootConfig\s*(\?\.|\.|\[)\s*['"]?ssoMode/);
  });
});
