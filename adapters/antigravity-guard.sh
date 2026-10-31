#!/bin/bash
# Antigravity PreToolUse adapter for the orin-dx PR-bot guard. Register it for ALL tools (run_command and
# the file tools: view_file, list_dir, grep_search, find_by_name, write_to_file, replace_file_content...).
#
# The shared guard understands Antigravity's payload ({"toolCall":{"name":..,"args":{"CommandLine":..,
# "Cwd":..}}} and path args such as AbsolutePath/TargetFile/DirectoryPath/SearchPath) directly; this
# adapter only maps the guard's verdict to Antigravity's {"decision":"deny","reason":...}.
#
# FAILS CLOSED: a missing guard, a missing HOME, an unreadable payload, a guard crash or any unexpected
# guard output all produce a deny. It prints nothing (allow) only when the guard exits 0 silently.
#
# Register it with an absolute path or with $HOME; do not use "~" in the hook command (it may not be
# expanded). UNVERIFIED against Antigravity's docs: the hook key names, the "decision"/"reason" output
# shape, and whether a non-zero exit is treated as deny. That is why this adapter always exits 0 and
# puts the verdict in JSON, which is what the previous adapter relied on.
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin
export PATH

deny() {
  local r=$1
  r=${r//\\/\\\\}
  r=${r//\"/\\\"}
  r=${r//$'\n'/ }
  r=${r//$'\t'/ }
  printf '{"decision":"deny","reason":"%s"}\n' "$r"
  exit 0
}

trap 'deny "orin-dx PR-bot guard adapter failed unexpectedly; blocking this tool call."' ERR

if [[ -z ${HOME:-} || ${HOME:0:1} != / ]]; then
  HOME=$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')
fi
[[ -n $HOME && ${HOME:0:1} == / ]] || deny "orin-dx PR-bot guard: cannot determine HOME; blocking tool calls."
export HOME

GUARD="$HOME/.config/orin-dx/pr-bot-guard.sh"
[[ -f $GUARD && -x $GUARD ]] || deny "orin-dx PR-bot guard is missing ($GUARD); blocking tool calls until it is restored."

payload=$(cat) || deny "orin-dx PR-bot guard: could not read the hook payload."
[[ -n $payload ]] || deny "orin-dx PR-bot guard: empty hook payload."

trap - ERR
out=$(printf '%s' "$payload" | "$GUARD" 2>/dev/null)
rc=$?

if ((rc == 0)) && [[ -z $out ]]; then
  exit 0
fi

reason=""
if ((rc == 2)) && command -v jq >/dev/null 2>&1; then
  reason=$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // empty' 2>/dev/null) || reason=""
fi
[[ -n $reason ]] || reason="orin-dx PR-bot guard blocked this tool call (guard exit $rc)."
deny "$reason"
