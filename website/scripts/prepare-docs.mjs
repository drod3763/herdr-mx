import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const websiteDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(websiteDir, '../..');
const publicDir = resolve(repoRoot, 'website/public');
const stableDocsDir = resolve(repoRoot, 'website/src/content/docs');
const previewDocsSourceDir = resolve(repoRoot, 'docs/next/website/src/content/docs');
const previewDocsDir = resolve(stableDocsDir, 'preview');

if (process.argv[2] === '--rewrite-preview-doc-fixture') {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  process.stdout.write(rewritePreviewDocContent(Buffer.concat(chunks).toString('utf8')));
} else {
  await preparePublicAssets();
  await preparePreviewDocs();
}

async function preparePublicAssets() {
  await rm(publicDir, { recursive: true, force: true });
  await mkdir(publicDir, { recursive: true });

  // Files that may legitimately be absent (preview.json only after a preview run; the manifest
  // signatures only after a signed release). Their absence must not fail a local/docs build.
  const optional = new Set([
    'preview.json',
    'latest.json.minisig',
    'preview.json.minisig',
  ]);
  for (const file of [
    'install.sh',
    'install.ps1',
    'agent-guide.md',
    'latest.json',
    'latest.json.minisig',
    'preview.json',
    'preview.json.minisig',
    'robots.txt',
    '_headers',
    '_redirects',
  ]) {
    const source = resolve(repoRoot, 'website', file);
    try {
      await cp(source, resolve(publicDir, file));
    } catch (error) {
      if (!optional.has(file) || error.code !== 'ENOENT') throw error;
    }
  }

  // The updater fails closed when <manifest>.minisig is missing, so a production/release deploy must
  // never publish a manifest without its signature. Enforce that when REQUIRE_MANIFEST_SIGNATURES=1
  // (set in the production/release deploy). Local and docs builds leave it unset, keeping the
  // sidecars optional so they don't need the signing key.
  if (process.env.REQUIRE_MANIFEST_SIGNATURES === '1') {
    for (const [manifest, signature] of [
      ['latest.json', 'latest.json.minisig'],
      ['preview.json', 'preview.json.minisig'],
    ]) {
      if (
        existsSync(resolve(publicDir, manifest)) &&
        !existsSync(resolve(publicDir, signature))
      ) {
        throw new Error(
          `${manifest} is being published without ${signature}; herdr clients require a signed ` +
            `manifest. Run the signing workflow (or restore the .minisig) before deploying.`,
        );
      }
    }
  }

  for (const directory of ['assets', 'css', 'agent-detection']) {
    await cp(resolve(repoRoot, 'website', directory), resolve(publicDir, directory), {
      recursive: true,
    });
  }
}

async function preparePreviewDocs() {
  await rm(previewDocsDir, { recursive: true, force: true });
  await copyPreviewDocs(previewDocsSourceDir, previewDocsDir);
}

async function copyPreviewDocs(sourceDir, destinationDir) {
  await mkdir(destinationDir, { recursive: true });
  for (const entry of await readdir(sourceDir, { withFileTypes: true })) {
    const source = join(sourceDir, entry.name);
    const destination = join(destinationDir, entry.name);
    if (entry.isDirectory()) {
      await copyPreviewDocs(source, destination);
      continue;
    }
    if (!entry.isFile()) continue;

    const content = await readFile(source, 'utf8');
    const relativePath = relative(previewDocsSourceDir, source);
    await writeFile(destination, rewritePreviewDocContent(content, relativePath), 'utf8');
  }
}

export function rewritePreviewDocContent(content, relativePath = '') {
  const rewritten = content
    .replaceAll('/docs/', '/docs/preview/')
    .replaceAll('../../../public/', '../../../../public/');
  return insertPreviewNotice(rewritten, relativePath);
}

function insertPreviewNotice(content, relativePath) {
  const notice = [
    '> Preview docs describe unreleased preview builds. Stable docs remain at [/docs/](/docs/).',
    '',
    '',
  ].join('\n');
  const indexPrefix =
    relativePath === 'index.mdx'
      ? content.replace('title: Herdr documentation', 'title: Herdr preview documentation')
      : content;
  const frontmatter = indexPrefix.match(/^---\n[\s\S]*?\n---\n/);
  if (!frontmatter) {
    return insertNoticeAfterImports(indexPrefix, notice);
  }
  const body = indexPrefix.slice(frontmatter[0].length);
  return `${frontmatter[0]}\n${insertNoticeAfterImports(body, notice)}`;
}

function insertNoticeAfterImports(content, notice) {
  const imports = content.match(/^(\s*import .+?;\n)+\s*/);
  if (!imports) {
    return `${notice}${content}`;
  }
  return `${imports[0]}${notice}${content.slice(imports[0].length)}`;
}
