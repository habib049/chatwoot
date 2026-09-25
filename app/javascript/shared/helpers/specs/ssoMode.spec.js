import { isSsoMode, getPortalUrl } from '../ssoMode';

const setLocation = (protocol, hostname, port = '') => {
  Object.defineProperty(window, 'location', {
    value: { protocol, hostname, port },
    writable: true,
    configurable: true,
  });
};

describe('ssoMode', () => {
  const originalLocation = window.location;

  afterEach(() => {
    delete window.chatwootConfig;
    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
      configurable: true,
    });
  });

  describe('isSsoMode', () => {
    it('is true only for boolean true', () => {
      window.chatwootConfig = { ssoMode: true };
      expect(isSsoMode()).toBe(true);
    });

    it.each([
      ['false', false],
      ["string 'true'", 'true'],
      ['undefined', undefined],
      ['null', null],
      ['number 1', 1],
      ['array', [true]],
    ])('is false for %s', (_, value) => {
      window.chatwootConfig = { ssoMode: value };
      expect(isSsoMode()).toBe(false);
    });

    it('is false when chatwootConfig is missing', () => {
      delete window.chatwootConfig;
      expect(isSsoMode()).toBe(false);
    });
  });

  describe('getPortalUrl', () => {
    it('swaps the first hostname label for smbName', () => {
      window.chatwootConfig = { ssoMode: true, smbName: 'portal' };
      setLocation('https:', 'chat.example.com');
      expect(getPortalUrl()).toBe('https://portal.example.com/');
    });

    it('keeps a non-default port', () => {
      window.chatwootConfig = { ssoMode: true, smbName: 'portal' };
      setLocation('http:', 'chat.example.test', '3000');
      expect(getPortalUrl()).toBe('http://portal.example.test:3000/');
    });

    it.each([
      ['empty', ''],
      ['undefined', undefined],
      ['number', 5],
      ['null', null],
    ])('throws when smbName is %s', (_, smbName) => {
      window.chatwootConfig = { ssoMode: true, smbName };
      setLocation('https:', 'chat.example.com');
      expect(() => getPortalUrl()).toThrow('SMB_NAME is required');
    });

    it('throws when chatwootConfig is missing', () => {
      setLocation('https:', 'chat.example.com');
      expect(() => getPortalUrl()).toThrow('SMB_NAME is required');
    });

    it('throws when the hostname has no dot', () => {
      window.chatwootConfig = { ssoMode: true, smbName: 'portal' };
      setLocation('http:', 'localhost');
      expect(() => getPortalUrl()).toThrow();
    });
  });
});
