#!/bin/zsh
# Builds Activity Observer from this checkout, installs it and connects it to
# the agents found on this Mac.
#
#   ./setup.sh                 build, install, connect every agent that is found
#   ./setup.sh --agent codex   connect only Codex (codex, claude, both or none)
#
# The installation asks once for the administrator password in this terminal.
# Nothing is downloaded while Activity Observer runs. The build fetches the
# pinned npm packages listed in UI/package-lock.json.
set -euo pipefail
ao_repo="${0:A:h}"
ao_agent=""
while (( $# )); do
  case "$1" in
    --agent) ao_agent="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) print -u2 "Unknown option: $1"; exit 64 ;;
  esac
done
if [[ -n "$ao_agent" && "$ao_agent" != (codex|claude|both|none) ]]; then
  print -u2 'Use --agent codex, claude, both or none'; exit 64
fi
if (( EUID == 0 )); then
  print -u2 'Run setup.sh as your own user. It asks for the administrator password when it is needed.'; exit 77
fi

ao_fail() { print -u2 "setup: $1"; exit 1; }
ao_os=$(/usr/bin/sw_vers -productVersion)
autoload -Uz is-at-least
is-at-least 14.2 "$ao_os" || ao_fail "macOS 14.2 or later is required (this Mac runs $ao_os)"
/usr/bin/xcrun --find clang >/dev/null 2>&1 || ao_fail 'The Xcode command line tools are required: xcode-select --install'
command -v node >/dev/null || ao_fail 'Node.js 22 or later is required'
ao_node_major=$(node -p 'process.versions.node.split(".")[0]')
(( ao_node_major >= 22 )) || ao_fail "Node.js 22 or later is required (found $(node -v))"

print '1/4  Installing the pinned build dependencies'
if [[ ! -d "$ao_repo/UI/node_modules" || "$ao_repo/UI/package-lock.json" -nt "$ao_repo/UI/node_modules" ]]; then
  (cd "$ao_repo/UI" && npm ci --ignore-scripts --no-audit --no-fund)
fi

print '2/4  Building and testing the collector, then preparing the installer'
"$ao_repo/prepare-protected-install.sh"

print '3/4  Installing the protected collector (administrator password required)'
"$ao_repo/build/Enable Protection.command"

ao_observer="$HOME/Library/Application Support/ActivityObserver UI/UI/observer"
[[ -x "$ao_observer" ]] || ao_fail 'The installation did not finish'

print '4/4  Connecting agents'
ao_connect() {
  if "$ao_observer" connect "$1"; then return 0; fi
  print -u2 "setup: could not connect $1. Run: \"$ao_observer\" connect $1"
}
case "${ao_agent:-auto}" in
  none) ;;
  codex|claude) ao_connect "$ao_agent" ;;
  both) ao_connect codex; ao_connect claude ;;
  auto)
    ao_found=0
    if [[ -x /Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex || -x /Applications/Codex.app/Contents/Resources/codex ]] || command -v codex >/dev/null; then
      ao_found=1; ao_connect codex
    fi
    if command -v claude >/dev/null || [[ -d "$HOME/Library/Application Support/Claude" || -d "$HOME/.claude" ]]; then
      ao_found=1; ao_connect claude
    fi
    (( ao_found )) || print 'No agent was found. Install Codex or Claude Code, then run this script again.'
    ;;
esac

"$ao_observer" doctor
print
print 'Activity Observer is installed and collecting.'
print 'Open Codex or Claude Code in the folder where security reviews should live and say:'
print '    Set up Activity Observer.'
print 'The agent then points real-time alerts at that chat, schedules the daily review and runs the first one.'
