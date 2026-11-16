#!/bin/zsh
# Removes Activity Observer from this Mac.
#
#   ./uninstall.sh            stop and remove the programs, keep the log and its signing key
#   ./uninstall.sh --purge    also delete the log, the signing key, reports and settings
#
# Asks once for the administrator password.
set -euo pipefail
ao_purge=0
[[ "${1:-}" == "--purge" ]] && ao_purge=1
if (( EUID == 0 )); then
  print -u2 'Run uninstall.sh as your own user.'; exit 77
fi
ao_uid=$(id -u)
ao_ui="$HOME/Library/Application Support/ActivityObserver UI"

# Agent registrations. A missing agent or plugin is not an error.
for ao_codex in /Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex /Applications/Codex.app/Contents/Resources/codex "$(command -v codex || true)"; do
  [[ -x "$ao_codex" ]] || continue
  "$ao_codex" plugin remove activity-observer@activity-observer-local >/dev/null 2>&1 || true
  "$ao_codex" plugin marketplace remove activity-observer-local >/dev/null 2>&1 || true
  break
done
for ao_claude in "$(command -v claude || true)" "$HOME/.claude/local/claude" "$HOME/.local/bin/claude" \
    "$HOME/Library/Application Support/Claude/claude-code"/*/*/claude.app/Contents/MacOS/claude(N); do
  [[ -x "$ao_claude" ]] || continue
  "$ao_claude" plugin uninstall activity-observer@activity-observer-local >/dev/null 2>&1 || true
  "$ao_claude" plugin marketplace remove activity-observer-local >/dev/null 2>&1 || true
  break
done
ao_desktop="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
if [[ -f "$ao_desktop" ]]; then
  /usr/bin/python3 - "$ao_desktop" <<'PY'
import json,sys,os
path=sys.argv[1]
data=json.load(open(path))
if data.get('mcpServers',{}).pop('activity-observer',None) is not None:
    temporary=path+'.activity-observer.tmp'
    with open(temporary,'w') as f: json.dump(data,f,indent=2); f.write('\n')
    os.chmod(temporary,os.stat(path).st_mode&0o777); os.replace(temporary,path)
PY
fi

for ao_job in local.activity-observer.incidents local.activity-observer.mcp; do
  /bin/launchctl bootout "gui/$ao_uid/$ao_job" 2>/dev/null || true
  if [[ -e "$HOME/Library/LaunchAgents/$ao_job.plist" ]]; then /bin/rm "$HOME/Library/LaunchAgents/$ao_job.plist"; fi
done

sudo /bin/zsh -s -- "$ao_uid" "$ao_purge" <<'ACTIVITY_OBSERVER_ROOT_UNINSTALL'
set -euo pipefail
ao_uid="$1"; ao_purge="$2"
ao_base='/Library/Application Support/ActivityObserver'
/bin/launchctl bootout "gui/$ao_uid/local.activity-observer.sensor" 2>/dev/null || true
/bin/launchctl bootout system/local.activity-observer.capture 2>/dev/null || true
/bin/launchctl bootout system/local.activity-observer.guard 2>/dev/null || true
for ao_file in /Library/LaunchAgents/local.activity-observer.sensor.plist /Library/LaunchDaemons/local.activity-observer.capture.plist \
    /Library/LaunchDaemons/local.activity-observer.guard.plist /Library/PrivilegedHelperTools/local.activity-observer \
    "$ao_base/capture.fifo" "$ao_base/install-manifest.json" /private/var/run/local.activity-observer.sock; do
  if [[ -e "$ao_file" || -L "$ao_file" ]]; then /bin/rm "$ao_file"; fi
done
for ao_directory in "$ao_base/policies" "$ao_base/bin"; do
  if [[ -d "$ao_directory" ]]; then /bin/rm -r "$ao_directory"; fi
done
if [[ "$ao_purge" == 1 && -d "$ao_base" ]]; then /bin/rm -r "$ao_base"; fi
ACTIVITY_OBSERVER_ROOT_UNINSTALL

if (( ao_purge )); then
  if [[ -d "$ao_ui" ]]; then /bin/rm -r "$ao_ui"; fi
  print 'Activity Observer and its data were removed.'
else
  for ao_part in dashboard-marketplace claude-marketplace; do
    if [[ -d "$ao_ui/$ao_part" ]]; then /bin/rm -r "$ao_ui/$ao_part"; fi
  done
  print 'Activity Observer was removed. The log, its signing key, published reports and settings were kept:'
  print '  /Library/Application Support/ActivityObserver'
  print "  $ao_ui"
  print 'Run ./uninstall.sh --purge to delete them, or ./setup.sh to install again and continue the same log.'
fi
