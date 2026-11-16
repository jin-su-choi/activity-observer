import {readFileSync,lstatSync} from 'node:fs';
import {resolve} from 'node:path';
import {installedUiDir} from './paths.mjs';

export const initialGenesisMarker='__ACTIVITY_OBSERVER_FIRST_INSTALL_GENESIS__';
export const initialKeyMarker='__ACTIVITY_OBSERVER_FIRST_INSTALL_KEY__';
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
// Pins for the installed collector, verifier, policies, signing key and log
// genesis. Only the installation transaction that the Mac's administrator
// authorized writes them. They are never inferred from the files in place.
export function validateTrust(value,initial=false){
  if(value?.schema!==1 || !['key','genesis','binary','verifier','policy'].every(name=>hash(value[name])||(initial&&((name==='key'&&value[name]===initialKeyMarker)||(name==='genesis'&&value[name]===initialGenesisMarker)))) ||
     !['guard','sensor'].every(name=>value[name]===undefined||hash(value[name])))throw Error('Invalid approved installation pins');
  return value;
}
// Returns null before the first installation.
export function readApprovedTrust(){
  const path=resolve(installedUiDir,'approved-trust.json');
  try{const s=lstatSync(path);if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o077)||s.size>4096)throw Error('Unsafe approved installation pins');return validateTrust(JSON.parse(readFileSync(path,'utf8')));}
  catch(error){if(error.code==='ENOENT')return null;throw error;}
}
