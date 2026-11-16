import {readFileSync,lstatSync,existsSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {initialKeyMarker,initialGenesisMarker,readApprovedTrust,validateTrust} from './trust.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const base='/Library/Application Support/ActivityObserver';
const binary='/Library/PrivilegedHelperTools/local.activity-observer';
const hash=p=>createHash('sha256').update(readFileSync(p)).digest('hex');
const prior=readApprovedTrust();
const installed=existsSync(binary)||existsSync(base+'/install-manifest.json');
let key,genesis,initialKey=false;
if(existsSync(base+'/public-key.der')&&!installed){
  // A key without a collector is left by an unfinished first installation or
  // by an uninstall that kept the log. Its root-owned receipt must match.
  const receiptPath=base+'/initial-enrollment.json';const info=lstatSync(receiptPath),publicInfo=lstatSync(base+'/public-key.der');
  if(!info.isFile()||info.uid!==0||(info.mode&0o022)||!publicInfo.isFile()||publicInfo.uid!==0||(publicInfo.mode&0o022))throw Error('Unsafe initial enrollment');
  const receipt=JSON.parse(readFileSync(receiptPath,'utf8'));
  if(receipt.user_id!==process.getuid()||receipt.key_fingerprint!==hash(base+'/public-key.der'))throw Error('Initial enrollment does not match');
  key=initialKeyMarker;genesis=initialGenesisMarker;initialKey=true;
}else if(existsSync(base+'/public-key.der')){
  if(!prior)throw Error('Activity Observer is installed on this Mac, but this account has no approved pins for it. Update it from the account that installed it.');
  for(const [path,expected]of [[base+'/public-key.der',prior.key],[binary,prior.binary],[base+'/bin/page-verify',prior.verifier],[base+'/policies/mcp.sb',prior.policy]]){
    const s=lstatSync(path);if(!s.isFile()||s.uid!==0||(s.mode&0o022)||hash(path)!==expected)throw Error('Approved operating artifact differs: '+path);
  }
  key=prior.key;genesis=prior.genesis;
}else{
  if(installed)throw Error('An existing installation is missing its key; do not initialize it');
  key=initialKeyMarker;genesis=initialGenesisMarker;initialKey=true;
}
const trust=validateTrust({schema:1,key,genesis,binary:hash(resolve(root,'build/activity-observer')),verifier:hash(resolve(root,'build/observer-page-verify')),
  policy:hash(resolve(root,'Policies/mcp.sb')),guard:hash(resolve(root,'Policies/guard.sb')),sensor:hash(resolve(root,'Policies/sensor.sb'))},initialKey);
writeFileSync(resolve(root,'build/ui-trust.json'),JSON.stringify({trust,initialKey}),{mode:0o600});
console.log(JSON.stringify({initialKey,preparedBinary:trust.binary}));
