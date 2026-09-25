import fs from 'fs';
import path from 'path';

const root = path.resolve(__dirname, '../../..');
const HELPER = path.join(root, 'shared/helpers/ssoMode.js');
const READS_FLAG =
  /chatwootConfig\s*(\?\.|\.|\[\s*['"`])\s*ssoMode|\{[^}]*\bssoMode\b[^}]*\}\s*=\s*window\.chatwootConfig/;

const walk = dir =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return walk(full);
    return /\.(js|vue|ts)$/.test(entry.name) ? [full] : [];
  });

describe('ssoMode single predicate', () => {
  it('only shared/helpers/ssoMode.js reads chatwootConfig.ssoMode', () => {
    const readers = walk(root).filter(
      file =>
        file !== HELPER &&
        !file.includes(`${path.sep}specs${path.sep}`) &&
        !/\.spec\.[jt]s$/.test(file) &&
        READS_FLAG.test(fs.readFileSync(file, 'utf8'))
    );
    expect(readers).toEqual([]);
  });

  it('the pattern detects a violating read', () => {
    expect(READS_FLAG.test('const a = window.chatwootConfig.ssoMode;')).toBe(
      true
    );
    expect(READS_FLAG.test('window.chatwootConfig?.ssoMode')).toBe(true);
    expect(READS_FLAG.test("window.chatwootConfig['ssoMode']")).toBe(true);
    expect(READS_FLAG.test('const { ssoMode } = window.chatwootConfig;')).toBe(
      true
    );
    expect(READS_FLAG.test('isSsoMode()')).toBe(false);
  });
});
