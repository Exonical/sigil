// Copies the Vite build into the backend's embedded dist directory. Only the .gitkeep there is tracked, so the
// build output never shows up in git status.
import { cpSync, existsSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const built = join(web, 'dist');
const embedded = resolve(web, '..', 'backend', 'internal', 'portal', 'dist');

if (!existsSync(join(built, 'index.html'))) {
  throw new Error('The web build has no index.html; run vite build first.');
}
for (const entry of readdirSync(embedded)) {
  if (entry !== '.gitkeep') rmSync(join(embedded, entry), { recursive: true, force: true });
}
cpSync(built, embedded, { recursive: true });
console.log(`copied ${built} to ${embedded}`);
