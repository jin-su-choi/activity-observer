import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, renameSync, existsSync, lstatSync, rmSync, chmodSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { homedir } from 'node:os';
import { resolve, dirname, relative } from 'node:path';

const ui=resolve(homedir(),'Library/Application Support/ActivityObserver UI/UI');
const label='local.activity-observer.mcp', incidents='local.activity-observer.incidents';
const domain=`gui/${process.getuid()}`;
const plist=resolve(homedir(),'Library/LaunchAgents',label+'.plist');
const incidentPlist=resolve(homedir(),'Library/LaunchAgents',incidents+'.plist');
const entries=['incident.sb','incident-launch.sh','incident-monitor.mjs','shared-server.mjs','mcp-server.mjs','mcp-relay','connection.json','approved-trust.json','cli.mjs','observer','widget-icons','install-incidents.mjs','release.json'];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const ctl=args=>execFileSync('/bin/launchctl',args,{timeout:12000,stdio:['ignore','pipe','pipe']});
const loaded=job=>{try{ctl(['print',domain+'/'+job]);return true;}catch{return false;}};
async function stop(job){if(!loaded(job))return;ctl(['bootout',domain+'/'+job]);for(let n=0;n<50;n++){if(!loaded(job))return;await delay(100);}throw Error('Service did not stop: '+job);}
async function start(path){if(!existsSync(path))return;for(let n=0;;n++){try{ctl(['bootstrap',domain,path]);return;}catch(e){if(n>=49)throw e;await delay(100);}}}
function atomic(path,bytes,mode=0o600){mkdirSync(dirname(path),{recursive:true,mode:0o700});const temp=path+'.deploy-'+process.pid;writeFileSync(temp,bytes,{flag:'wx',mode});renameSync(temp,path);chmodSync(path,mode);}
function saved(path){if(!existsSync(path))return null;const s=lstatSync(path);if(!s.isFile()||s.uid!==process.getuid())throw Error('Unexpected deployment file: '+path);return {mode:s.mode&0o777,bytes:readFileSync(path).toString('base64')};}
function verifyRelease(descriptor){
  if(!descriptor.release.startsWith(ui+'/releases/'))throw Error('Unexpected prepared release');
  for(const [file,hash] of Object.entries(descriptor.files)){
    if(file.includes('..')||file.startsWith('/'))throw Error('Invalid release member');
    const path=resolve(descriptor.release,file),s=lstatSync(path);
    if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o022)||sha(readFileSync(path))!==hash)throw Error('Prepared UI changed: '+file);
  }
}
export function restoreSnapshots(snapshot){
  for(const [path,value] of Object.entries(snapshot)){
    if(value)atomic(path,Buffer.from(value.bytes,'base64'),value.mode);
    else rmSync(path,{force:true});
  }
}
export async function deploymentStep(mode,descriptor){
  if(process.getuid()===0)throw Error('UI deployment must run as the desktop user');
  const journal=resolve(ui,'.deployment.json');
  if(mode==='prepare'){
    verifyRelease(descriptor);
    if(existsSync(journal))throw Error('An unfinished deployment needs rollback before another update');
    const files=Object.fromEntries([...entries.map(n=>resolve(ui,n)),plist].map(p=>[p,saved(p)]));
    const state={descriptor,files,sharedLoaded:loaded(label),incidentLoaded:loaded(incidents),activated:false};
    atomic(journal,JSON.stringify(state));
    // Prevent the previous detector from flagging the authorized binary swap.
    await stop(incidents);
    return {prepared:true};
  }
  if(!existsSync(journal)){if(['rollback','resume'].includes(mode))return {noTransaction:true};throw Error('Missing UI deployment transaction');}
  const state=JSON.parse(readFileSync(journal,'utf8'));
  if(state.descriptor.release!==descriptor.release)throw Error('Deployment identity changed');
  if(mode==='activate'){
    verifyRelease(descriptor);
    let release=descriptor.release;
    const marker='__ACTIVITY_OBSERVER_FIRST_INSTALL_KEY__';
    const key=descriptor.bound_key ?? descriptor.trust?.key;
    if(!/^[a-f0-9]{64}$/.test(key))throw Error('A pinned operational key is required');
    if(descriptor.initialKey){
      if(descriptor.trust?.key!==marker||descriptor.trust?.genesis!=='__ACTIVITY_OBSERVER_FIRST_INSTALL_GENESIS__'||!/^[a-f0-9]{64}$/.test(descriptor.bound_genesis))throw Error('Invalid initial-key preparation');
      release=mkdtempSync(resolve(ui,'releases','enrolled-'));state.boundRelease=release;atomic(journal,JSON.stringify(state));
      for(const name of Object.keys(descriptor.files)){
        const from=resolve(descriptor.release,name);let bytes=readFileSync(from);
        if(name.endsWith('.mjs')||name.endsWith('.next'))bytes=Buffer.from(bytes.toString('utf8').replaceAll(marker,key).replaceAll('__ACTIVITY_OBSERVER_FIRST_INSTALL_GENESIS__',descriptor.bound_genesis));
        atomic(resolve(release,name),bytes,lstatSync(from).mode&0o777);
      }
      mkdirSync(resolve(release,'dist'),{recursive:true,mode:0o700});
    }else if(key!==descriptor.trust?.key)throw Error('An update cannot change the operational key');
    await stop(label);
    for(const [from,to] of [['policy.next','incident.sb'],['launcher.next','incident-launch.sh'],['monitor.next','incident-monitor.mjs'],['mcp-relay','mcp-relay'],['entry.next','mcp-server.mjs'],['approved-trust.next','approved-trust.json'],
        ['cli.next','cli.mjs'],['observer.next','observer'],['widget-icons','widget-icons'],['incidents-installer.next','install-incidents.mjs']])
      atomic(resolve(ui,to),readFileSync(resolve(release,from)),['mcp-relay','observer','widget-icons'].includes(to)?0o700:0o600);
    // The agent installers and the skills they copy stay in the release.
    atomic(resolve(ui,'release.json'),JSON.stringify({release})+'\n');
    atomic(resolve(ui,'shared-server.mjs'),`import { startSharedServer } from ${JSON.stringify('./'+relative(ui,release)+'/shared-server.mjs')};\nconst service=await startSharedServer();\nfor(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>service.close().finally(()=>process.exit(0)));\n`);
    execFileSync(process.execPath,[resolve(release,'install-shared.mjs'),'--service-only'],{timeout:30000,stdio:['ignore','pipe','pipe']});
    state.activated=true;atomic(journal,JSON.stringify(state));
    return {activated:true};
  }
  if(mode==='rollback'){
    await stop(label);restoreSnapshots(state.files);if(state.boundRelease)rmSync(state.boundRelease,{recursive:true,force:true});state.activated=false;state.restored=true;atomic(journal,JSON.stringify(state));return {restored:true};
  }
  if(mode==='resume'){
    // Called only after the root writer has been restored or committed.
    if(state.restored&&state.sharedLoaded&&!loaded(label))await start(plist);
    if(state.incidentLoaded&&!loaded(incidents))await start(incidentPlist);
    rmSync(journal);return {resumed:true};
  }
  throw Error('Invalid deployment step');
}
if(['prepare','activate','rollback','resume'].includes(process.argv[1])){
  try{console.log(JSON.stringify(await deploymentStep(process.argv[1],JSON.parse(process.argv[2]))));}
  catch(error){console.error(error.message);process.exitCode=1;}
}
