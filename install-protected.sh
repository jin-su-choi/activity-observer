#!/bin/zsh
set -euo pipefail
if (( EUID != 0 )); then
  print -u2 'Use the verified, administrator-authorized installation command. This script does not elevate itself.'
  exit 77
fi
ao_uid=""
ao_expected=""
while (( $# )); do
  case "$1" in
    --user) ao_uid="$2"; shift 2 ;;
    --expected-sha) ao_expected="$2"; shift 2 ;;
    *) print -u2 "Unknown option: $1"; exit 64 ;;
  esac
done
ao_source="${0:A:h}/activity-observer"
/usr/bin/python3 - "$ao_uid" "$ao_expected" "$ao_source" <<'PY'
import os,sys,stat,pwd,hashlib,subprocess,pathlib,plistlib,time,json,tempfile
uid_text,expected,source_text=sys.argv[1:]
if not uid_text.isdecimal() or int(uid_text)==0: raise SystemExit('A non-root user ID is required')
uid=int(uid_text);user=pwd.getpwuid(uid);source=pathlib.Path(source_text)
if len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected): raise SystemExit('An exact approved SHA-256 is required')
s=source.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022: raise SystemExit('The staged executable must be a root-owned regular file')
if hashlib.sha256(source.read_bytes()).hexdigest()!=expected: raise SystemExit('Executable does not match the approved build')
subprocess.run(['/usr/bin/codesign','--verify','--strict',str(source)],check=True)
signature=subprocess.run(['/usr/bin/codesign','-dv','--verbose=2',str(source)],capture_output=True,text=True)
if 'runtime' not in signature.stderr: raise SystemExit('Hardened Runtime is missing')
base=pathlib.Path('/Library/Application Support/ActivityObserver');data=base/'data';private=base/'private'
binary=pathlib.Path('/Library/PrivilegedHelperTools/local.activity-observer')
policy_dir=base/'policies';bin_dir=base/'bin';page_verify=bin_dir/'page-verify'
capture_fifo=base/'capture.fifo';public_key=base/'public-key.der';manifest=base/'install-manifest.json';enrollment=base/'initial-enrollment.json'
guard_plist=pathlib.Path('/Library/LaunchDaemons/local.activity-observer.guard.plist')
capture_plist=pathlib.Path('/Library/LaunchDaemons/local.activity-observer.capture.plist')
sensor_plist=pathlib.Path('/Library/LaunchAgents/local.activity-observer.sensor.plist')
sandbox='/usr/bin/sandbox-exec'
gui=f'gui/{uid}'
jobs=[('system',capture_plist),('system',guard_plist),(gui,sensor_plist)]
def launchctl(*args):
    return subprocess.run(['/bin/launchctl',*args],capture_output=True,text=True,timeout=12)
gui_active=launchctl('print',gui).returncode==0

def read_safe_file(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
        raise SystemExit('Unsafe root-owned artifact: '+str(path))
    return path.read_bytes(),stat.S_IMODE(info.st_mode)

def replace_file(path,content,mode):
    with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.observer-',delete=False) as f:
        temporary=pathlib.Path(f.name)
        try:
            os.fchmod(f.fileno(),mode)
            f.write(content);f.flush();os.fsync(f.fileno())
            os.replace(temporary,path)
        finally:
            if temporary.exists():temporary.unlink()

def directory(path,mode):
    if path.exists() or path.is_symlink():
        st=path.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode): raise SystemExit('Unsafe directory: '+str(path))
    else: path.mkdir()
    os.chown(path,0,0);os.chmod(path,mode)
    subprocess.run(['/bin/chmod','-N',str(path)],check=True)
for p,m in [(base,0o755),(data,0o700),(private,0o700),(policy_dir,0o755),(bin_dir,0o755)]:directory(p,m)
if not binary.parent.exists():
    binary.parent.mkdir(mode=0o755);os.chown(binary.parent,0,0)
policies={role:policy_dir/f'{role}.sb' for role in ('guard','sensor','mcp','mcp-http','relay')}
profiles={role:read_safe_file(source.parent/p.name)[0] for role,p in policies.items()}
verified_page=read_safe_file(source.parent/'page-verify')[0]
ui_descriptor=json.loads(read_safe_file(source.parent/'ui-release.json')[0])
ui_script=read_safe_file(source.parent/'deploy-release.mjs')[0].decode('utf8')
if not pathlib.Path(ui_descriptor['node']).is_absolute():raise SystemExit('Invalid prepared Node path')
def ui_step(mode):
    command=['/usr/bin/sudo','-n','-H','-u',f'#{uid}',ui_descriptor['node'],'--input-type=module','-e',ui_script,mode,json.dumps(ui_descriptor)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=90,cwd=user.pw_dir)
    if result.returncode:raise RuntimeError('UI deployment '+mode+' failed: '+result.stderr[-1500:])
    return json.loads(result.stdout)

for role,rules in profiles.items():
    if role=='relay':continue
    # Test the staged policy with the approved staged executable before stopping a job.
    fixture=rules.decode('utf8').replace(str(binary),str(source))
    subprocess.run([sandbox,'-D','AO_NODE='+str(source),'-p',fixture,str(source),'check-network-isolation'],
                   check=True,capture_output=True,timeout=10)
files=[binary,page_verify,*policies.values(),guard_plist,capture_plist,sensor_plist,manifest]
previous={p:read_safe_file(p) if p.exists() or p.is_symlink() else None for p in files}
if previous[manifest] and json.loads(previous[manifest][0]).get('user_id')!=uid:
    raise SystemExit('The existing installation belongs to a different GUI user')
if previous[binary] and not public_key.is_file():raise SystemExit('Existing installation is missing its public key')
prior_key=read_safe_file(public_key)[0] if public_key.exists() or public_key.is_symlink() else None
prepared_trust=ui_descriptor.get('trust',{})
initial=ui_descriptor.get('initialKey') is True
if initial:
    if previous[binary] or previous[manifest] or prepared_trust.get('key')!='__ACTIVITY_OBSERVER_FIRST_INSTALL_KEY__':
        raise SystemExit('Initial enrollment cannot replace an existing installation')
    if prior_key is not None:
        receipt=json.loads(read_safe_file(enrollment)[0]) if enrollment.exists() else {}
        if receipt.get('key_fingerprint')!=hashlib.sha256(prior_key).hexdigest() or receipt.get('user_id')!=uid:
            raise SystemExit('The existing key has no approved initial-enrollment receipt')
else:
    if prior_key is None or prepared_trust.get('key')!=hashlib.sha256(prior_key).hexdigest():
        raise SystemExit('An update cannot change the approved operational key')
if prepared_trust.get('binary')!=expected or prepared_trust.get('verifier')!=hashlib.sha256(verified_page).hexdigest() or any(prepared_trust.get(pin)!=hashlib.sha256(profiles[role]).hexdigest() for pin,role in (('policy','mcp'),('guard','guard'),('sensor','sensor'))):
    raise SystemExit('Prepared UI pins differ from the approved installation artifacts')
loaded={(domain,p):launchctl('print',f'{domain}/{p.stem}').returncode==0 for domain,p in jobs}
had_fifo=capture_fifo.exists() or capture_fifo.is_symlink()
if had_fifo:
    info=capture_fifo.lstat()
    if not stat.S_ISFIFO(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise SystemExit('Unsafe capture pipe')

def stop_jobs():
    for domain,p in reversed(jobs):
        label=f'{domain}/{p.stem}'
        if launchctl('print',label).returncode!=0:continue
        launchctl('bootout',label)
        for _ in range(30):
            if launchctl('print',label).returncode!=0:break
            time.sleep(.2)
        else:raise RuntimeError('Could not stop '+label)

def bootstrap(domain,path):
    r=launchctl('bootstrap',domain,str(path))
    if r.returncode and launchctl('print',f'{domain}/{path.stem}').returncode:
        raise RuntimeError(f'Could not register {path.stem}: {r.stderr.strip()}')

legacy=pathlib.Path(user.pw_dir)/'Library/Application Support/ActivityObserver/data/events.sqlite'
archive=data/'legacy-unsealed.sqlite'
if legacy.exists() and not archive.exists():
    fd=os.open(legacy,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_size>90*1024*1024: raise SystemExit('Unexpected legacy log file')
        out=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        digest=hashlib.sha256()
        try:
            while True:
                chunk=os.read(fd,1024*1024)
                if not chunk:break
                digest.update(chunk)
                view=memoryview(chunk)
                while view: view=view[os.write(out,view):]
            os.fsync(out)
        finally: os.close(out)
        (data/'legacy-unsealed.json').write_text(json.dumps({'sealed_copy_created_at':time.time(),'sha256':digest.hexdigest(),'notice':'Historical user-writable logs copied as observed; not evidence of integrity before protected installation.'}))
    finally:os.close(fd)
ui_prepared=False
core_started=False
try:
    ui_prepared=True
    ui_step('prepare')
    core_started=True
    switch_started_at=time.time()
    stop_jobs()
    launchctl('bootout',f'{gui}/local.activity-observer')
    for p in data.iterdir():
        info=p.lstat()
        if not stat.S_ISREG(info.st_mode):raise RuntimeError('Unexpected entry in protected data: '+str(p))
        os.chown(p,0,0);os.chmod(p,0o600)
    replace_file(binary,source.read_bytes(),0o755)
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=expected:raise RuntimeError('Installed executable hash mismatch')
    replace_file(page_verify,verified_page,0o755)
    for role,path in policies.items():replace_file(path,profiles[role],0o644)
    if not had_fifo:os.mkfifo(capture_fifo,0o600)
    subprocess.run(['/bin/chmod','-N',str(capture_fifo)],check=True)
    if prior_key is None:
        subprocess.run([str(binary),'prepare-protected-key'],check=True,capture_output=True,timeout=12)
    current_key=read_safe_file(public_key)[0]
    if prior_key is not None and current_key!=prior_key:raise RuntimeError('Operational key changed during install')
    key=hashlib.sha256(current_key).hexdigest()
    ui_descriptor['bound_key']=key
    if initial and prior_key is None:replace_file(enrollment,json.dumps({'key_fingerprint':key,'user_id':uid}).encode(),0o644)

    common={'RunAtLoad':True,'ProcessType':'Background','LowPriorityIO':True,'Nice':10,'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null'}
    # Sensors.m uses the same predicate when it runs without the protected writer.
    predicate="(process == 'ControlCenter' AND category == 'sensor-indicators') OR (process == 'replayd' AND (eventMessage CONTAINS 'accepted client connection' OR eventMessage CONTAINS 'SLContentStream start:' OR eventMessage CONTAINS 'SLContentStream stop:')) OR (subsystem == 'com.apple.TCC' AND eventMessage BEGINSWITH 'AUTHREQ_')"
    configs={
        guard_plist:{**common,'KeepAlive':True,'ThrottleInterval':10,
                     'ProgramArguments':[sandbox,'-f',str(policies['guard']),str(binary),'guard','--directory',str(data),'--user',str(uid)]},
        sensor_plist:{**common,'KeepAlive':{'SuccessfulExit':False},'ThrottleInterval':10,'LimitLoadToSessionType':'Aqua',
                      'ProgramArguments':[sandbox,'-f',str(policies['sensor']),str(binary),'agent','--directory',str(data),'--user',str(uid)]},
        capture_plist:{**common,'KeepAlive':True,'ThrottleInterval':10,
                       'ProgramArguments':['/bin/sh','-c','exec > "$1"; shift; exec "$@"',
                                           'activity-observer-capture',str(capture_fifo),'/bin/launchctl','asuser',str(uid),
                                           '/usr/bin/sudo','-n','-H','-u',f'#{uid}','/usr/bin/log','stream',
                                           '--style','ndjson','--level','info','--predicate',predicate]}
    }
    for path,config in configs.items():
        replace_file(path,plistlib.dumps({'Label':path.stem,**config}),0o644)
    for domain,p in jobs:
        if domain!=gui or gui_active:bootstrap(domain,p)

    # Verify the writer's own signed heartbeat before using a GUI client.
    # Startup can include an audit of the full retained event chain.
    command=[sandbox,'-D','AO_NODE='+str(binary),'-f',str(policies['mcp']),str(binary),'status',
             '--directory',str(data),'--protected-file','--expected-key',key]
    deadline=time.monotonic()+180
    sensors={}
    last_probe={}
    while time.monotonic()<deadline:
        probe=subprocess.run(command,capture_output=True,text=True,timeout=14)
        last_probe={'exit':probe.returncode,'error':probe.stderr.strip()[:300]}
        if probe.returncode==0:
            status=json.loads(probe.stdout)
            sensors={k:v['status'] for k,v in status.get('sensors',{}).items()}
            required=['guard_network_isolation']
            if gui_active:required+=['guard_capture_feed','guard_sensor_liveness','sensor_network_isolation','install_update','input_taps','hid','capture','audio']
            if status.get('status_signature_valid') and status.get('started',0)>=switch_started_at and all(sensors.get(name)=='active' for name in required):break
        else:
            try:last_probe['error']=json.loads(probe.stdout).get('error') or last_probe['error']
            except ValueError:pass
        time.sleep(1)
    else:raise RuntimeError('Isolation or required sensor did not become healthy: '+json.dumps({'sensors':sensors,'probe':last_probe}))
    if initial:
        receipt=json.loads(read_safe_file(enrollment)[0])
        genesis=status.get('boundary_hash') if status.get('boundary_id')==0 else receipt.get('genesis')
        if not isinstance(genesis,str) or len(genesis)!=64:raise RuntimeError('Initial signed genesis is unavailable')
        if prepared_trust.get('genesis')!='__ACTIVITY_OBSERVER_FIRST_INSTALL_GENESIS__':raise RuntimeError('Initial genesis preparation differs')
        ui_descriptor['bound_genesis']=genesis
        replace_file(enrollment,json.dumps({**receipt,'genesis':genesis}).encode(),0o644)
    ui_step('activate')
    deployment={'version':status.get('version','unknown'),'sha256':expected,'max_data_bytes':1000000000,'retention_policy':'capacity',
                'key_fingerprint':key,'installed_at':time.time(),'user_id':uid,'executable':str(binary),
                'policies':{role:hashlib.sha256(profile).hexdigest() for role,profile in profiles.items()},
                'page_verifier_sha256':hashlib.sha256(verified_page).hexdigest()}
    replace_file(manifest,json.dumps(deployment,indent=2).encode(),0o644)
    ui_step('resume')
    ui_prepared=False
except BaseException as failure:
    recovery_errors=[]
    if ui_prepared:
        try:ui_step('rollback')
        except BaseException as e:recovery_errors.append(str(e))
    if core_started:
        try:
            stop_jobs()
            for path,saved in previous.items():
                if saved:replace_file(path,*saved)
                elif path.exists():path.unlink()
            if not had_fifo and capture_fifo.exists():capture_fifo.unlink()
            for (domain,path),was_loaded in loaded.items():
                if was_loaded and previous[path]:bootstrap(domain,path)
        except BaseException as e:recovery_errors.append(str(e))
    if ui_prepared:
        try:ui_step('resume')
        except BaseException as e:recovery_errors.append(str(e))
    if recovery_errors:raise RuntimeError(str(failure)+'; rollback needs attention: '+'; '.join(recovery_errors)) from failure
    raise
print(json.dumps({'protected_service_registered':True,'binary':str(binary),'data':str(data),'user':user.pw_name,'sensor_registered':gui_active},ensure_ascii=False))
PY
