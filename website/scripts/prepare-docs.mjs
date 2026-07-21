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
const previewConfigReferenceSource = resolve(
  repoRoot,
  'docs/next/website/src/data/config-reference.json',
);
const previewConfigReferenceDestination = resolve(
  repoRoot,
  'website/src/data/config-reference-preview.json',
);

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

  // The updater fetches <manifest>.minisig before parsing the manifest, so an unsigned manifest is
  // unusable to clients and must never be served. But publishing the docs site must not depend on
  // the signing key, so a missing sidecar never takes the whole site down. Therefore:
  //   - manifest + sidecar both present  -> publish both (already copied above);
  //   - manifest present, sidecar absent -> DROP the manifest from the published output (and warn),
  //     so the docs site still deploys while no unsigned manifest is ever served — the updater then
  //     simply finds no manifest (a soft "couldn't check for updates") instead of fetching one whose
  //     signature 404s;
  //   - REQUIRE_MANIFEST_SIGNATURES=1 (release/production pipelines that guarantee sidecars) turns a
  //     missing sidecar into a hard build failure instead of a silent drop, so a broken signing step
  //     can't quietly ship an empty update channel.
  const requireSignatures = process.env.REQUIRE_MANIFEST_SIGNATURES === '1';
  for (const [manifest, signature] of [
    ['latest.json', 'latest.json.minisig'],
    ['preview.json', 'preview.json.minisig'],
  ]) {
    const manifestPath = resolve(publicDir, manifest);
    const signaturePath = resolve(publicDir, signature);
    if (existsSync(manifestPath) && !existsSync(signaturePath)) {
      if (requireSignatures) {
        throw new Error(
          `${manifest} is being published without ${signature}; herdr clients require a signed ` +
            `manifest. Run the signing workflow (or restore the .minisig) before deploying.`,
        );
      }
      console.warn(
        `warning: ${manifest} has no ${signature}; dropping it from the published output so no ` +
          `unsigned manifest is served. Sign it (or set REQUIRE_MANIFEST_SIGNATURES=1 to fail the ` +
          `build) to publish the update channel.`,
      );
      await rm(manifestPath, { force: true });
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
  await cp(previewConfigReferenceSource, previewConfigReferenceDestination);
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
    .replaceAll('../../../public/', '../../../../public/')
    // Preview docs live one directory deeper than stable docs, so component
    // imports need one more parent segment regardless of locale depth. Only
    // MDX import lines are rewritten; prose mentioning relative paths is not.
    .replace(/^(import .*from\s+['"])(?=(?:\.\.\/)+components\/)/gm, '$1../');
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
