// Bundles @noble/ciphers (AES-CBC) + @noble/hashes (MD5) and inlines everything into index.html.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
mkdirSync('dist', { recursive: true });
await build({ entryPoints: ['src/noble-entry.js'], bundle: true, minify: true, format: 'iife', globalName: 'Noble', outfile: 'dist/noble.min.js' });
const html = readFileSync('src/template.html', 'utf8')
  .replace('/*NOBLE*/', () => readFileSync('dist/noble.min.js', 'utf8').trim())
  .replace('/*PROTO*/', () => readFileSync('src/proto.js', 'utf8'));
writeFileSync('index.html', html);
console.log('index.html', html.length, 'bytes');
