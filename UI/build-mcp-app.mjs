import { build } from 'esbuild';
import { cp, mkdir, mkdtemp, writeFile, readFile, rename, rm, readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderAppHtml, prepareViewData } from './build-widget.mjs';
import { readApprovedTrust, validateTrust } from './trust.mjs';
import { deploymentStep } from './deploy-release.mjs';
import { digest, installedUiDir, installedReviewDir, publishReview, readPublishedReview } from './published-review.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const install = args.includes('--install');
const prepareRelease=args.includes('--prepare-release');
const sandbox = '/usr/bin/sandbox-exec';
if(install&&prepareRelease)throw Error('Choose install or prepare-release');
const trustIndex=args.indexOf('--trust-file');
if(trustIndex>=0&&(!prepareRelease||!args[trustIndex+1]))throw Error('A trust file is only valid with prepare-release');
const enrollment=trustIndex>=0?JSON.parse(await readFile(resolve(args[trustIndex+1]),'utf8')):{trust:readApprovedTrust(),initialKey:false};
// A build without pins is only for local development and previews.
const trust=enrollment.trust?validateTrust(enrollment.trust,enrollment.initialKey===true):null;
if((install||prepareRelease)&&!(trust?.guard&&trust.sensor))throw Error('Run ./prepare-protected-install.sh first. It records the approved collector and policy pins.');
const definitions=trust&&{AO_MCP_INSTALLED:'true',AO_APPROVED_KEY:JSON.stringify(trust.key),AO_APPROVED_GENESIS:JSON.stringify(trust.genesis),AO_APPROVED_BINARY:JSON.stringify(trust.binary),AO_APPROVED_VERIFIER:JSON.stringify(trust.verifier),AO_APPROVED_POLICY:JSON.stringify(trust.policy),AO_APPROVED_GUARD_POLICY:JSON.stringify(trust.guard),AO_APPROVED_SENSOR_POLICY:JSON.stringify(trust.sensor)};
const [snapshot] = args.filter((arg,i)=>!['--install','--prepare-release'].includes(arg)&&(trustIndex<0||(i!==trustIndex&&i!==trustIndex+1)));
const dist = resolve(dir, 'dist');
const manifestPath = resolve(dist, 'manifest.json');
const manifest = await readFile(manifestPath, 'utf8').then(JSON.parse).catch(error => {
  if (error.code === 'ENOENT') return {};
  throw error;
});
await mkdir(dist, { recursive: true });
// Both display languages are bundled into the widgets. Writing their text as
// UTF-8 instead of escapes keeps the HTML within its size budget.
const result = await build({ entryPoints: [resolve(dir, 'mcp-app.mjs')], bundle: true, minify: true,
  format: 'iife', platform: 'browser', target: 'es2022', charset: 'utf8', write: false, legalComments: 'inline' });
const runtime = result.outputFiles[0].text;
await writeFile(resolve(dist, 'runtime.js'), runtime);
await build({ entryPoints: [resolve(dir, 'local-host.mjs')], bundle: true, minify: true, format: 'esm',
  platform: 'browser', target: 'es2022', charset: 'utf8', outfile: resolve(dist, 'local-host.js') });
const html = renderAppHtml(runtime);
await writeFile(resolve(dist, 'activity-review.html'), html);
const incidentRuntime = await build({ entryPoints: [resolve(dir, 'incident-app.mjs')], bundle: true, minify: true,
  format: 'iife', platform: 'browser', target: 'es2022', charset: 'utf8', write: false, legalComments: 'inline' });
const incidentTemplate = await readFile(resolve(dir, 'incident.template.html'), 'utf8');
const incidentHtml = incidentTemplate.replace('__INCIDENT_RUNTIME__', () => incidentRuntime.outputFiles[0].text.replaceAll('</script', '<\\/script'));
const incidentHtmlSha256 = digest(incidentHtml);
await writeFile(resolve(dist, 'incident.html'), incidentHtml);
if (snapshot) {
  const data = JSON.parse(await readFile(resolve(snapshot), 'utf8'));
  const view = JSON.stringify(prepareViewData(data));
  await writeFile(resolve(dist, 'review.view.json'), view, { mode: 0o600 });
  Object.assign(manifest, { viewSha256: digest(view), after: data.source.after,
    through: data.source.through, headHash: data.source.anchor.payload.head_hash });
}
const htmlSha256 = digest(html);
const dashboardIcon = await readFile(resolve(dir, 'assets/activity-observer.png'));
const presentation = { schema: 1, htmlSha256, incidentHtmlSha256, dashboardIconSha256: digest(dashboardIcon) };
await writeFile(resolve(dist, 'activity-observer.png'), dashboardIcon);
await writeFile(manifestPath, JSON.stringify({ ...manifest, ...presentation }, null, 2) + '\n', { mode: 0o600 });
let serverPath = resolve(dir, 'mcp-server.mjs');
if (install || prepareRelease) {
  // Desktop hosts launch the installed adapter without opening the external
  // project volume. The protected collector remains at its original path.
  await mkdir(dirname(installedUiDir), { recursive: true, mode: 0o700 });
  await mkdir(installedReviewDir, { recursive: true, mode: 0o700 });
  const installedBundle = entryPoint => build({ entryPoints: [entryPoint], bundle: true, write: false,
    format: 'esm', platform: 'node', target: 'node22', legalComments: 'inline',
    define: definitions });
  const staging = await mkdtemp(resolve(installedUiDir, '.release-'));
  const release = resolve(installedUiDir, 'releases', basename(staging).slice('.release-'.length));
  try {
    const [server, monitor, shared, sharedInstaller, dashboardInstaller, claudeInstaller, incidentInstaller, commandLine] = await Promise.all([
      installedBundle(serverPath),
      installedBundle(resolve(dir, 'incident-monitor.mjs')),
      installedBundle(resolve(dir, 'shared-server.mjs')),
      build({entryPoints:[resolve(dir,'install-shared.mjs')],bundle:true,write:false,format:'esm',platform:'node',target:'node22',define:{...definitions,AO_PREPARED_RELEASE:'true'}}),
      installedBundle(resolve(dir,'install-dashboard.mjs')),
      installedBundle(resolve(dir,'install-claude.mjs')),
      installedBundle(resolve(dir,'install-incidents.mjs')),
      installedBundle(resolve(dir,'cli.mjs'))
    ]);
    const relayPath = resolve(staging, 'mcp-relay');
    const relay = spawnSync('/usr/bin/xcrun', ['clang', '-O2', '-fobjc-arc', '-Wno-deprecated-declarations',
      resolve(dir, 'mcp-relay.m'), '-framework', 'Foundation', '-lcurl', '-o', relayPath], { encoding: 'utf8' });
    if (relay.status !== 0) throw Error(relay.stderr || 'Could not build the desktop MCP adapter');
    const icons = spawnSync('/usr/bin/xcrun', ['clang', '-O2', '-fobjc-arc', resolve(dir, 'app-icons.m'), '-framework', 'AppKit',
      '-o', resolve(staging, 'widget-icons')], { encoding: 'utf8' });
    if (icons.status !== 0) throw Error(icons.stderr || 'Could not build the icon reader');
    // The command-line tool runs without network access, except for the two
    // commands that have to start an agent's own command-line tool.
    const stable = name => JSON.stringify(resolve(installedUiDir, name)).replaceAll('$', '\\$');
    const launcher = [
      '#!/bin/sh',
      'node=' + JSON.stringify(process.execPath).replaceAll('$', '\\$'),
      // Node marks its built-in SQLite as experimental on every start.
      'quiet=--disable-warning=ExperimentalWarning',
      'case "$1:${2:-}" in',
      '  alerts:here|connect:*) exec "$node" $quiet ' + stable('cli.mjs') + ' "$@" ;;',
      '  *) exec /usr/bin/sandbox-exec -f ' + stable('incident.sb') + ' "$node" $quiet ' + stable('cli.mjs') + ' "$@" ;;',
      'esac', ''
    ].join('\n');
    const previous = await readPublishedReview(dist).catch(error => {
      console.error('Skipping invalid legacy review:', error.message);
      return null;
    });
    const existing = await readPublishedReview(installedReviewDir).catch(() => true);
    if (previous && !existing) await publishReview(previous, installedReviewDir);
    await Promise.all([
      writeFile(resolve(staging,'approved-trust.next'),JSON.stringify(trust),{mode:0o600}),
      writeFile(resolve(staging,'install-shared.mjs'),sharedInstaller.outputFiles[0].contents,{mode:0o600}),
      writeFile(resolve(staging,'install-dashboard.mjs'),dashboardInstaller.outputFiles[0].contents,{mode:0o600}),
      writeFile(resolve(staging,'install-claude.mjs'),claudeInstaller.outputFiles[0].contents,{mode:0o600}),
      writeFile(resolve(staging,'incidents-installer.next'),incidentInstaller.outputFiles[0].contents,{mode:0o600}),
      writeFile(resolve(staging,'cli.next'),commandLine.outputFiles[0].contents,{mode:0o600}),
      writeFile(resolve(staging,'observer.next'),launcher,{mode:0o600}),
      cp(resolve(dir,'../plugin/skills'),resolve(staging,'skills'),{recursive:true}),
      writeFile(resolve(staging, 'mcp-server.mjs'), server.outputFiles[0].contents, { mode: 0o600 }),
      writeFile(resolve(staging, 'shared-server.mjs'), shared.outputFiles[0].contents, { mode: 0o600 }),
      writeFile(resolve(staging, 'activity-review.html'), html, { mode: 0o600 }),
      writeFile(resolve(staging, 'incident.html'), incidentHtml, { mode: 0o600 }),
      writeFile(resolve(staging, 'activity-observer.png'), dashboardIcon, { mode: 0o600 }),
      writeFile(resolve(staging, 'manifest.json'), JSON.stringify(presentation) + '\n', { mode: 0o600 }),
      writeFile(resolve(staging, 'monitor.next'), monitor.outputFiles[0].contents, { mode: 0o600 }),
      writeFile(resolve(staging, 'launcher.next'), await readFile(resolve(dir, 'incident-launch.sh')), { mode: 0o600 }),
      writeFile(resolve(staging, 'policy.next'), await readFile(resolve(dir, '../Policies/incident.sb')), { mode: 0o600 }),
      writeFile(resolve(staging, 'entry.next'), `process.execve(${JSON.stringify(resolve(installedUiDir, 'mcp-relay'))}, [${JSON.stringify(resolve(installedUiDir, 'mcp-relay'))}], process.env);\n`, { mode: 0o600 })
    ]);
    await mkdir(resolve(staging,'assets'),{mode:0o700});
    await writeFile(resolve(staging,'assets/activity-observer.png'),dashboardIcon,{mode:0o600});
    await mkdir(resolve(staging,'Policies'),{mode:0o700});
    for(const role of ['mcp-http','relay'])await writeFile(resolve(staging,'Policies',role+'.sb'),await readFile(resolve(dir,'../Policies',role+'.sb')),{mode:0o600});
    await mkdir(resolve(staging,'dist'),{mode:0o700});
    await mkdir(dirname(release), { recursive: true, mode: 0o700 });
    await rename(staging, release);
    const installedServer = resolve(release, 'mcp-server.mjs');
    const checkPolicy=prepareRelease ? resolve(dir,'../Policies/mcp.sb') : '/Library/Application Support/ActivityObserver/policies/mcp.sb';
    const check = spawnSync(sandbox, ['-D', 'AO_NODE=' + process.execPath, '-f', checkPolicy,
      process.execPath, installedServer, prepareRelease ? '--check-bundle' : '--check-install'], { encoding: 'utf8', timeout: 15000 });
    if (check.status !== 0) {
      await rm(release, { recursive: true, force: true });
      throw Error(check.stderr?.trim() || check.error?.message || 'The installed MCP release could not start');
    }
    const files={};
    for(const entry of await readdir(release,{recursive:true,withFileTypes:true}))if(entry.isFile()){const path=resolve(entry.parentPath,entry.name);files[path.slice(release.length+1)]=digest(await readFile(path));}
    const descriptor={release,node:process.execPath,files,trust,initialKey:enrollment.initialKey===true};
    if(prepareRelease){
      await writeFile(resolve(dist,'prepared-release.json'),JSON.stringify(descriptor),{mode:0o600});
    }else{
      let prepared=false;
      try{prepared=true;await deploymentStep('prepare',descriptor);await deploymentStep('activate',descriptor);await deploymentStep('resume',descriptor);prepared=false;}
      catch(error){if(prepared){await deploymentStep('rollback',descriptor);await deploymentStep('resume',descriptor);}throw error;}
      serverPath=resolve(installedUiDir,'mcp-server.mjs');
    }

  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}
const server = install ? {
  command: sandbox,
  args: ['-D', 'AO_NODE=' + process.execPath, '-f', '/Library/Application Support/ActivityObserver/policies/mcp.sb',
    process.execPath, serverPath, '--stdio']
} : { command: process.execPath, args: [serverPath, '--stdio'] };
await writeFile(resolve(dist, 'mcp-config.json'), JSON.stringify({ mcpServers: { 'activity-observer': server } }, null, 2) + '\n');
console.log(JSON.stringify({ htmlBytes: Buffer.byteLength(html), runtimeBytes: Buffer.byteLength(runtime) }));
