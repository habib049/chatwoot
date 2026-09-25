// The one frontend SSO-mode predicate. The flag is emitted by vueapp.html.erb from the
// backend SsoMode predicate; it only hides UI, the server gates never depend on it.
export const isSsoMode = () => window.chatwootConfig?.ssoMode === true;

// Portal host = current host with its first label replaced by SMB_NAME. Throws on
// missing config so logout never redirects to a wrong host.
export const getPortalUrl = () => {
  const smbName = window.chatwootConfig?.smbName;
  if (typeof smbName !== 'string' || smbName === '') {
    throw new Error('SMB_NAME is required');
  }
  const { protocol, hostname, port } = window.location;
  if (!hostname.includes('.')) {
    throw new Error(`Cannot derive portal host from '${hostname}'`);
  }
  const host = hostname.replace(/^[^.]*\./, `${smbName}.`);
  return `${protocol}//${host}${port ? `:${port}` : ''}/`;
};
