// Generates the TypeScript client for the admin API from proto/sigil/admin/v1/admin.proto.
// The proto is copied into a temporary module first, because buf needs the module root as its input.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const staging = mkdtempSync(join(tmpdir(), 'sigil-admin-proto-'));
try {
  const target = join(staging, 'sigil', 'admin', 'v1');
  mkdirSync(target, { recursive: true });
  copyFileSync(resolve(web, '..', 'proto', 'sigil', 'admin', 'v1', 'admin.proto'), join(target, 'admin.proto'));
  execFileSync(
    'npx',
    ['--no-install', 'buf', 'generate', staging, '--template', join(web, 'buf.gen.yaml'), '--output', join(web, 'src', 'gen')],
    { cwd: web, stdio: 'inherit', shell: true },
  );
} finally {
  rmSync(staging, { recursive: true, force: true });
}
