#!/bin/zsh
# Builds the collector and the local MCP release from this checkout and writes
# build/Enable Protection.command. That command installs exactly these files:
# it copies them to a root-only directory and checks each SHA-256 recorded here
# before anything runs with privileges.
set -euo pipefail
ao_project="${0:A:h}"
"$ao_project/build.sh"
/usr/bin/xcrun clang -O2 -fobjc-arc -Wno-deprecated-declarations "$ao_project/UI/verify-page.m" \
  -framework Foundation -framework Security -o "$ao_project/build/observer-page-verify"
ao_node=$(command -v node)
[[ -n "$ao_node" ]] || { print -u2 "Node.js is required"; exit 1; }
"$ao_node" "$ao_project/UI/prepare-release-trust.mjs"
"$ao_node" "$ao_project/UI/build-mcp-app.mjs" --prepare-release --trust-file "$ao_project/build/ui-trust.json"
/usr/bin/python3 - "$ao_project" <<'PY'
from pathlib import Path
import os,sys,hashlib,shlex,json
root=Path(sys.argv[1])
artifacts={'activity-observer':root/'build/activity-observer','install-protected.sh':root/'install-protected.sh',
           'page-verify':root/'build/observer-page-verify','ui-release.json':root/'UI/dist/prepared-release.json','deploy-release.mjs':root/'UI/deploy-release.mjs',
           **{role+'.sb':root/'Policies'/f'{role}.sb' for role in ('guard','sensor','mcp','mcp-http','relay')}}
hashes={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in artifacts.items()}
q=shlex.quote
commands=[]
for name,path in artifacts.items():
    target='"$ao_stage"/'+q(name)
    commands.append(f'/usr/bin/install -m 0700 {q(str(path))} {target}')
    commands.append(f'ao_sum=$(/usr/bin/shasum -a 256 {target})')
    commands.append(f'[[ "${{ao_sum%% *}}" == {q(hashes[name])} ]] || {{ print -u2 {q("Approved artifact hash mismatch: "+name)}; exit 1; }}')
body='''#!/bin/zsh
set -euo pipefail
# Copies the approved artifacts into a private root-owned staging directory and
# checks their pinned hashes before executing either artifact with privileges.
sudo /bin/zsh <<'ACTIVITY_OBSERVER_ROOT_INSTALL'
set -euo pipefail
ao_stage=$(/usr/bin/mktemp -d /var/root/activity-observer-install.XXXXXX)
trap '/bin/rm -rf -- "$ao_stage"' EXIT
STAGE_COMMANDS
/bin/zsh "$ao_stage/install-protected.sh" --user OWNER_UID --expected-sha BINARY_HASH
ACTIVITY_OBSERVER_ROOT_INSTALL
'''
body=body.replace('STAGE_COMMANDS','\n'.join(commands)).replace('BINARY_HASH',q(hashes['activity-observer'])).replace('OWNER_UID',str(os.getuid()))
target=root/'build/Enable Protection.command';target.write_text(body);target.chmod(0o700)
print(json.dumps({'installer':str(target),'approved_binary_sha256':hashes['activity-observer'],'approved_installer_sha256':hashes['install-protected.sh'],'artifacts':hashes},ensure_ascii=False))
PY
