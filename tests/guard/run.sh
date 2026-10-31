#!/bin/bash
# Table-driven tests for bin/pr-bot-guard.sh, adapters/antigravity-guard.sh and gh-shim's repo parsing.
# No network: a fake `gh` is put first on the guard's pinned PATH (the test copy rewrites the one
# GUARD_PATH line) and answers `gh pr list --head <branch>` from the branch name:
#   bot-*  -> app/orin-dx-pr-bot     human-* -> castrog     none-* -> (no PRs)
#   err-*  -> exit 1                 slow-*  -> hangs (guard timeout, shortened to 2 s for the test)
# HOME is a throwaway directory with fake protected files, so nothing real is read.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
GUARD_SRC="$ROOT/bin/pr-bot-guard.sh"
ADAPTER="$ROOT/adapters/antigravity-guard.sh"
SHIM="$ROOT/bin/gh-shim"

T=$(mktemp -d "${TMPDIR:-/tmp}/guardtest.XXXXXX")
trap 'rm -rf "$T"' EXIT
FH="$T/home" # fake HOME
mkdir -p "$FH/.config/orin-dx" "$FH/.cache/orin-dx" "$FH/.local/bin" "$FH/.claude" "$FH/.config/other" \
  "$FH/Library/Caches/OrinDX-PR-Bot" "$FH/Library/Application Support/OrinDX-PR-Bot" "$T/bin" "$T/repos"
echo dummy >"$FH/.config/orin-dx/pr-bot-token"
echo dummy >"$FH/.config/orin-dx/notes.txt"
echo '{}' >"$FH/.claude/settings.json"

# Fake gh: only the read-only pr list call is expected.
cat >"$T/bin/gh" <<EOF
#!/bin/bash
echo "\$*" >>"$T/gh.log"
[[ \$1 == pr && \$2 == list ]] || { echo "UNEXPECTED gh \$*" >>"$T/gh.log"; exit 99; }
head=""
while ((\$#)); do [[ \$1 == --head ]] && head=\$2; shift; done
case \$head in
  bot-*) echo app/orin-dx-pr-bot ;;
  human-*) echo castrog ;;
  none-*) ;;
  err-*) exit 1 ;;
  slow-*) sleep 30 ;;
esac
EOF
chmod +x "$T/bin/gh"

# Test copy of the guard: fake gh first on the pinned PATH, shorter timeout. Nothing else changes.
GUARD="$T/guard.sh"
sed -e "s#^GUARD_PATH=.*#GUARD_PATH=$T/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin#" \
  -e 's#^GH_TIMEOUT=.*#GH_TIMEOUT=2#' "$GUARD_SRC" >"$GUARD"
chmod +x "$GUARD"
grep -q "^GUARD_PATH=$T/bin:" "$GUARD" || {
  echo "could not build the test guard"
  exit 1
}
cp "$GUARD" "$FH/.config/orin-dx/pr-bot-guard.sh" # where the adapter looks for it

mkrepo() { # name remote-url branch
  local d="$T/repos/$1"
  mkdir -p "$d"
  git -C "$d" init -q
  git -C "$d" remote add origin "$2"
  git -C "$d" symbolic-ref HEAD "refs/heads/$3"
}
mkrepo orin-bot git@github.com:orin-dx/callisto.git bot-feature
mkrepo orin-human https://github.com/orin-dx/callisto.git human-feature
mkrepo orin-none git@github.com:Orin-DX/callisto.git none-feature
mkrepo orin-err git@github.com:orin-dx/callisto.git err-feature
mkrepo orin-slow git@github.com:orin-dx/callisto.git slow-feature
mkrepo other https://github.com/castrog/thing.git human-feature
mkdir -p "$T/repos/plain"

declare -a CWDS
cwd_of() {
  case $1 in
    orin) echo "$T/repos/orin-bot" ;;
    home) echo "$FH" ;;
    *) echo "$T/repos/$1" ;;
  esac
}

PASS=0
FAIL=0
N=0
FAILS=""

verdict() { # rc out -> allow|deny|error
  local rc=$1 out=$2
  if ((rc == 2)); then
    echo deny
  elif ((rc == 0)) && [[ -z $out ]]; then
    echo allow
  elif ((rc == 0)) && [[ $out == *'"deny"'* ]]; then
    echo deny
  else
    echo "error(rc=$rc)"
  fi
}

record() { # expect got label
  N=$((N + 1))
  if [[ $1 == "$2" ]]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    FAILS+=$'\n'"  FAIL #$N expected $1 got $2: $3"
  fi
}

run_payload() { # payload -> sets GOT (VERBOSE=1 prints each deny reason)
  local out rc
  out=$(printf '%s' "$1" | env -i HOME="$FH" TMPDIR="$T" /bin/bash "$GUARD" 2>"$T/err")
  rc=$?
  GOT=$(verdict "$rc" "$out")
  [[ ${VERBOSE:-0} == 1 && -s $T/err ]] && printf '    #%d %s\n' $((N + 1)) "$(head -c 160 "$T/err")"
  return 0
}

# c: Claude Code Bash payload; a: Antigravity run_command payload; v: Codex argv-array payload
t() { # expect shape cwd-key command
  local exp=$1 shape=$2 cwd payload
  cwd=$(cwd_of "$3")
  case $shape in
    c) payload=$(jq -n --arg c "$4" --arg d "$cwd" '{tool_name:"Bash",tool_input:{command:$c},cwd:$d}') ;;
    a) payload=$(jq -n --arg c "$4" --arg d "$cwd" '{toolCall:{name:"run_command",args:{CommandLine:$c,Cwd:$d}}}') ;;
    v) payload=$(jq -n --argjson c "$4" --arg d "$cwd" '{tool_name:"Bash",tool_input:{command:$c},cwd:$d}') ;;
  esac
  run_payload "$payload"
  record "$exp" "$GOT" "[$shape@$3] $4"
}

tj() { # expect raw-json (with @CWD@ and @HOME@ placeholders)
  local p=${2//@CWD@/$T/repos/orin-bot}
  p=${p//@HOME@/$FH}
  run_payload "$p"
  record "$1" "$GOT" "[json] $2"
}

ta() { # expect payload-json  (through the Antigravity adapter with the fake HOME)
  local out rc p=${2//@CWD@/$T/repos/orin-human}
  p=${p//@HOME@/$FH}
  out=$(printf '%s' "$p" | env -i HOME="${3:-$FH}" TMPDIR="$T" /bin/bash "$ADAPTER" 2>/dev/null)
  rc=$?
  if ((rc == 0)) && [[ -z $out ]]; then GOT=allow
  elif ((rc == 0)) && [[ $out == *'"decision":"deny"'* ]]; then GOT=deny
  else GOT="error(rc=$rc)"; fi
  record "$1" "$GOT" "[adapter] $2"
}

# ------------------------------------------------------------------------------------------------
# Benign commands that must stay allowed
# ------------------------------------------------------------------------------------------------
t allow c orin 'git status'
t allow c orin 'git commit -m "fix: handle merge of pr data"'
t allow c orin 'pnpm install && pnpm test'
t allow c orin 'gh pr view 12'
t allow c orin 'gh pr list --state open --json number,title'
t allow c orin 'gh pr checks 12'
t allow c orin 'gh run view 123 --log'
t allow c orin 'gh pr create --fill'
t allow c orin 'gh pr new --title "Add x" --body "Adds x"'
t allow c orin '~/.local/bin/gh pr create --fill'
t allow c orin 'gh pr comment 12 --body "addressed"'
t allow c orin-human 'entire status'
t allow c orin-human 'entire trail list'
t allow c orin 'ls -la ~/.config'
t allow c orin 'cat README.md | grep -n foo'
t allow c orin 'gh api repos/orin-dx/callisto/pulls'
t allow c orin 'gh api -X GET repos/orin-dx/callisto/pulls -f state=open'
t allow c orin "gh api graphql -f query='query { viewer { login } }'"
t allow c orin 'curl -fsSL https://api.github.com/repos/orin-dx/callisto/pulls'
t allow c other 'gh pr merge 5 --squash'
t allow c orin $'git commit -F - <<\'EOF\'\nDon\'t merge yet; it\'s a draft.\nEOF'
t allow c orin 'echo "built at $(date)"'
t allow c orin "find . -name '*.ts' -not -path './node_modules/*'"
t allow c orin 'rg TODO src'
t allow c other 'eval "$(fnm env)"'
t allow c orin '/opt/homebrew/bin/gh pr view 3'
t allow c orin 'cat ~/.claude/settings.json'
t allow c plain 'echo aGVsbG8K | base64 -d | sh'
t allow c orin $'gh pr create --title "feat: x" --body "$(cat <<\'EOF\'\n## Summary\nDon\'t merge (yet).\nEOF\n)"'
t allow c orin $'git commit -m "$(cat <<\'EOF\'\nfix: it\'s fine (really)\n\nCo-Authored-By: x\nEOF\n)"'
t allow c orin 'npm run build 2>&1 | tail -50'
t allow c orin 'for f in src/*.ts; do echo "$f"; done'
t allow c orin 'if [ -f x ]; then echo y; fi'
t allow c orin 'grep -rn "foo" src/'
t allow c orin 'env | grep GH'
t allow c orin 'entire --version'
t allow c orin "awk '{print \$1}' f.txt | sort | uniq -c"
t allow c orin "python3 -c 'import json; print(json.dumps({\"a\": 1}))'"
t allow c orin 'cd src && ls -la && cd ..'
t allow a orin 'gh pr view 12'
t allow a orin-human 'entire status'
t allow v orin '["git","status"]'

# ------------------------------------------------------------------------------------------------
# R1 protected names and paths (quotes, $HOME/~, globs, braces, .., cd, interpreters)
# ------------------------------------------------------------------------------------------------
t deny c orin 'cat ~/.config/orin-dx/pr-bot-token'
t deny c orin 'cat "$HOME/.config/orin-dx/pr-bot-token"'
t deny c orin "cat ~/.conf''ig/orin-dx/notes.txt"
t deny c orin 'cat ~/.config/orin-d?/*'
t deny c orin 'cat ~/.c*/orin*/pr-bot-t*'
t deny c orin 'cat ~/.config/orin-{dx,zz}/notes.txt'
t deny c orin 'cat ~/.c{onfig,x}/orin-dx/notes.txt'
t deny c orin 'cd ~/.config && cat orin-dx/notes.txt'
t deny c orin 'cat ~/.config/other/../orin-dx/notes.txt'
t deny c orin 'cp ${HOME}/.cache/orin-dx/x /tmp/y'
t deny c orin 'bash ~/.config/orin-dx/pr-bot-token'
t deny c orin 'python3 "$HOME/.cache/orin-dx/x.py"'
t deny c orin 'node ~/Library/Caches/OrinDX-PR-Bot/x.js'
t deny c orin "sh -c 'cat ~/.config/orin-dx/notes.txt'"
t deny c orin 'cat "$X/.config/orin-dx/notes.txt"'
t deny c orin "python3 -c 'print(open(\"/Users/someone/.config/\" + \"orin-dx/x\").read())'"
t deny c orin "age -d -i id.txt key.age"
t deny a orin 'cat ~/.config/orin-dx/pr-bot-token'
t deny c home 'ls .config/orin-dx'

# ------------------------------------------------------------------------------------------------
# R2 recursive tools over an ancestor of the protected dirs
# ------------------------------------------------------------------------------------------------
t deny c orin 'grep -r token ~/.config'
t deny c orin 'rg -uu token ~'
t deny c orin 'tar czf /tmp/x.tgz ~/Library'
t deny c orin "find ~ -name '*.pem'"
t allow c orin 'ls -la ~'

# ------------------------------------------------------------------------------------------------
# R3 the real gh / shim bypasses
# ------------------------------------------------------------------------------------------------
t deny c other '/opt/homebrew/bin/gh pr create --fill'
t deny c orin '/opt/homebrew/Cellar/gh/2.103.3/bin/gh pr create --fill'
t deny c orin 'command -p gh pr create --fill'
t deny c orin 'PATH=/opt/homebrew/bin:$PATH gh pr create --fill'
t deny c orin 'export PATH=/opt/homebrew/bin:$PATH; gh pr create --fill'
t deny c orin 'env -i PATH=/opt/homebrew/bin gh pr create --fill'
t deny c orin 'env -P /opt/homebrew/bin gh pr new'
t deny c orin 'sudo -u me /usr/local/bin/gh pr merge 1'
t deny c orin 'cp /opt/homebrew/bin/gh ./g'
t deny c orin './g pr create --fill'
t deny c orin 'alias gh=/opt/homebrew/bin/gh; gh pr create --fill'
t deny c orin 'hash -p /opt/homebrew/bin/gh gh; gh pr create'
t deny c other '/usr/local/bin/gh api -X PUT repos/castrog/thing/pulls/1/merge'

# ------------------------------------------------------------------------------------------------
# R4 gh pr write verbs in orin-dx repos (incl. quoting/env/bash -c normalisation and repo forms)
# ------------------------------------------------------------------------------------------------
t deny c orin 'gh pr merge 5 --squash'
t deny c orin 'gh pr review 5 --approve'
t deny c orin 'gh pr ready 5'
t deny c orin 'gh pr edit 5 --title x'
t deny c orin 'gh pr close 5'
t deny c orin 'gh pr reopen 5'
t deny c orin '"gh" pr merge 5'
t deny c orin "g''h pr merge 5"
t deny c orin 'g\h pr merge 5'
t deny c orin $'$\'\\x67\\x68\' pr merge 5'
t deny c orin 'env GH_DEBUG=1 gh pr merge 5'
t deny c orin "bash -c 'gh pr merge 5'"
t deny c orin "bash -lc \"cd . && gh pr ready 5\""
t deny c orin 'echo 5 | xargs -I{} gh pr merge {}'
t deny c orin 'find . -maxdepth 0 -exec gh pr merge 5 \;'
t deny c orin 'x=$(gh pr merge 5)'
t deny c orin $'gh pr create --body "$(cat <<\'EOF\'\nDon\'t\nEOF\n)" && gh pr merge 5'
t deny c orin $'x="$(cat <<EOF\n$(gh pr ready 5)\nEOF\n)"'
t deny c other 'gh pr merge 5 -R orin-dx/callisto'
t deny c plain 'gh pr merge --repo=github.com/orin-dx/callisto 5'
t deny c plain 'gh pr merge -Rorin-dx/callisto 5'
t deny c plain 'gh pr merge https://github.com/orin-dx/callisto/pull/5'
t deny c plain 'GH_REPO=orin-dx/callisto gh pr merge 5'
t deny c orin 'gh pr create --web'
t deny c orin 'gh pr create -dw'
t deny c orin 'gh pm 5'
t deny c other "gh alias set pm 'pr merge'"
t deny c orin 'gh $SUB 5'
t deny v orin '["bash","-lc","gh pr merge 5"]'
t deny a orin 'gh pr merge 5'

# ------------------------------------------------------------------------------------------------
# R5 gh api writes (REST endpoints, GraphQL)
# ------------------------------------------------------------------------------------------------
t deny c orin 'gh api -X PUT repos/orin-dx/callisto/pulls/5/merge'
t deny c plain 'gh api repos/orin-dx/callisto/pulls -f title=x -f head=b -f base=main'
t deny c orin 'gh api repos/{owner}/{repo}/pulls/5/reviews -f event=APPROVE'
t deny c plain 'gh api --method=POST repos/orin-dx/callisto/pulls/5/reviews'
t deny c plain "gh api graphql -f query='mutation { mergePullRequest(input:{pullRequestId:\"X\"}) { clientMutationId } }'"
t deny c plain 'gh api graphql -F query=@q.graphql'
t deny c plain 'gh api graphql --input body.json'
t allow c plain 'gh api repos/castrog/thing/pulls -f title=x -f head=b -f base=main'

# ------------------------------------------------------------------------------------------------
# R6 curl / wget / httpie to the GitHub API
# ------------------------------------------------------------------------------------------------
t deny c plain 'curl -X PUT -H "Authorization: token x" https://api.github.com/repos/orin-dx/callisto/pulls/5/merge'
t deny c plain "curl -d '{\"title\":\"x\"}' https://api.github.com/repos/orin-dx/callisto/pulls"
t deny c plain "curl https://api.github.com/graphql -d '{\"query\":\"mutation{mergePullRequest(input:{}){clientMutationId}}\"}'"
t deny c plain 'wget --method=PUT https://api.github.com/repos/orin-dx/callisto/pulls/5/merge'
t deny c plain 'http POST api.github.com/repos/orin-dx/callisto/pulls title=x'
t deny c orin 'curl -X POST "$URL" -d @body.json'

# ------------------------------------------------------------------------------------------------
# R7 entire trail link|create|merge|approve
# ------------------------------------------------------------------------------------------------
t allow c orin-bot 'entire trail link'
t allow c orin-bot 'entire trail merge'
t deny c orin-human 'entire trail link'
t deny c orin-none 'entire trail create --title x'
t deny c orin-human 'entire trail approve'
t deny c orin-err 'entire trail link'
t deny c orin-slow 'entire trail link'
t allow c other 'entire trail link'
t deny c orin-human "bash -c 'entire trail link'"
t deny c orin-human 'npx entire trail create'
t deny c orin-human '/opt/homebrew/bin/entire trail link'
t deny c orin-human 'cd "$D" && entire trail link'
t deny c orin-human 'entire trail $VERB'
t deny a orin-human 'entire trail link'

# ------------------------------------------------------------------------------------------------
# R8 code the guard cannot see
# ------------------------------------------------------------------------------------------------
t deny c orin 'bash -c "$(printf %s x)"'
t deny c orin 'echo Z2ggcHIgbWVyZ2UgNQo= | base64 -d | sh'
t deny c orin 'eval "$CMD"'
t deny c orin 'bash <<EOF
gh pr merge 5
EOF'
t deny c other 'echo Z2ggcHIgbWVyZ2UgNQo= | base64 -d | bash -s gh'

# ------------------------------------------------------------------------------------------------
# R9 the shim and hook configs
# ------------------------------------------------------------------------------------------------
t deny c orin 'echo x > ~/.local/bin/gh'
t deny c orin "sed -i '' 's/guard//' ~/.claude/settings.json"
t deny c orin 'rm ~/.codex/hooks.json'

# ------------------------------------------------------------------------------------------------
# R10 fail closed
# ------------------------------------------------------------------------------------------------
t deny c orin 'echo "unterminated'
t deny c orin 'echo $(unclosed'
tj deny 'this is not json'
tj deny ''
tj deny '[1,2,3]'

# ------------------------------------------------------------------------------------------------
# File tools (Claude Read/Grep/Glob/Write, Antigravity view_file, Codex apply_patch)
# ------------------------------------------------------------------------------------------------
tj deny '{"tool_name":"Read","tool_input":{"file_path":"@HOME@/.config/orin-dx/pr-bot-token"},"cwd":"@CWD@"}'
tj allow '{"tool_name":"Read","tool_input":{"file_path":"@CWD@/README.md"},"cwd":"@CWD@"}'
tj deny '{"tool_name":"Grep","tool_input":{"pattern":"token","path":"@HOME@"},"cwd":"@CWD@"}'
tj allow '{"tool_name":"Grep","tool_input":{"pattern":"pr-bot-token","path":"@CWD@/src"},"cwd":"@CWD@"}'
tj deny '{"tool_name":"Glob","tool_input":{"pattern":"orin-d*/*","path":"@HOME@/.config"},"cwd":"@CWD@"}'
tj deny '{"tool_name":"Glob","tool_input":{"pattern":"@HOME@/.c*/orin*/*"},"cwd":"@CWD@"}'
tj deny '{"tool_name":"Write","tool_input":{"file_path":"@HOME@/.claude/settings.json","content":"{}"},"cwd":"@CWD@"}'
tj allow '{"tool_name":"Edit","tool_input":{"file_path":"@CWD@/README.md","old_string":"a","new_string":"pr-bot-token docs"},"cwd":"@CWD@"}'
tj deny '{"toolCall":{"name":"view_file","args":{"AbsolutePath":"@HOME@/Library/Caches/OrinDX-PR-Bot/jwt"}}}'
tj deny '{"toolCall":{"name":"list_dir","args":{"DirectoryPath":"@HOME@/.cache/orin-dx"}}}'
tj deny '{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: @HOME@/.local/bin/gh\n@@\n-a\n+b\n*** End Patch"},"cwd":"@CWD@"}'
tj allow '{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: src/a.ts\n@@\n-a\n+b\n*** End Patch"},"cwd":"@CWD@"}'

# ------------------------------------------------------------------------------------------------
# Antigravity adapter (fails closed)
# ------------------------------------------------------------------------------------------------
ta allow '{"toolCall":{"name":"run_command","args":{"CommandLine":"git status","Cwd":"@CWD@"}}}'
ta deny '{"toolCall":{"name":"run_command","args":{"CommandLine":"entire trail link","Cwd":"@CWD@"}}}'
ta deny '{"toolCall":{"name":"view_file","args":{"AbsolutePath":"@HOME@/.config/orin-dx/pr-bot-token"}}}'
ta deny 'garbage'
mkdir -p "$T/emptyhome"
ta deny '{"toolCall":{"name":"run_command","args":{"CommandLine":"git status","Cwd":"@CWD@"}}}' "$T/emptyhome"

# The guard must only ever have asked gh the read-only question.
if grep -q UNEXPECTED "$T/gh.log" 2>/dev/null; then
  record ok unexpected-gh-call "fake gh saw a non-read call: $(grep UNEXPECTED "$T/gh.log" | head -1)"
else
  record ok ok "fake gh saw only read-only 'gh pr list' calls"
fi

# ------------------------------------------------------------------------------------------------
# gh-shim repo parsing (sourced; no gh is run)
# ------------------------------------------------------------------------------------------------
tp() { # expect-owner/name value
  local got
  got=$(
    # shellcheck disable=SC1090
    source "$SHIM" >/dev/null 2>&1
    if parse_repo "$1"; then echo "$R_HOST:$R_OWNER/$R_NAME"; else echo none; fi
  )
  record "$2" "$got" "[shim parse_repo] $1"
}
tp 'orin-dx/callisto' 'github.com:orin-dx/callisto'
tp 'github.com/Orin-DX/callisto' 'github.com:orin-dx/callisto'
tp 'https://github.com/orin-dx/callisto.git' 'github.com:orin-dx/callisto'
tp 'https://github.com/orin-dx/callisto/pull/5' 'github.com:orin-dx/callisto'
tp 'git@github.com:orin-dx/callisto.git' 'github.com:orin-dx/callisto'
tp 'ghe.example.com/orin-dx/callisto' 'ghe.example.com:orin-dx/callisto'
tp 'callisto' 'none'

# ------------------------------------------------------------------------------------------------
# gh-shim `pr create` decisions (sourced; fake real gh and fake mint; no network)
# ------------------------------------------------------------------------------------------------
cat >"$T/fakereal" <<'EOF'
#!/bin/bash
if [[ $1 == repo && $2 == view ]]; then
  case $PWD in */orin-*) echo orin-dx/callisto ;; */other) echo castrog/thing ;; *) exit 1 ;; esac
  exit 0
fi
echo "REAL $* TOKEN=${GH_TOKEN:-none} CFG=${GH_CONFIG_DIR:-default}"
EOF
chmod +x "$T/fakereal"
MINT="$FH/.config/orin-dx/pr-bot-token"
cat >"$MINT" <<EOF
#!/bin/bash
env >"$T/mint.env"
[[ -e "$T/mint.fail" ]] && exit 1
echo ghs_abcdefghijklmnopqrstuvwxyz0123456789
EOF
chmod 700 "$MINT"

ts() { # expect(bot|human|refuse|noauth) repo-dir args...
  local exp=$1 dir=$2 out rc got
  shift 2
  out=$(
    exec 2>/dev/null
    cd "$T/repos/$dir" || exit 9
    # shellcheck disable=SC1090
    source "$SHIM"
    REAL=$T/fakereal
    HOME_DIR=$FH
    USER_NAME=tester
    pr_create "$@"
  ) 2>/dev/null
  rc=$?
  if ((rc != 0)); then got=refuse
  elif [[ $out == *TOKEN=ghs_* ]]; then got=bot
  elif [[ $out == *TOKEN=none*CFG=default* ]]; then got=human
  elif [[ $out == *TOKEN=none* ]]; then got=noauth
  else got="error($out)"; fi
  record "$exp" "$got" "[shim@$dir] gh $*"
}
ts bot orin-bot pr create --fill
ts bot orin-bot pr new --fill
ts human other pr create --fill
ts bot other pr create -R orin-dx/callisto --fill
ts bot other pr create --repo=https://github.com/orin-dx/callisto.git --fill
ts bot other pr create -R github.com/Orin-DX/callisto --fill
ts bot plain pr create -Rorin-dx/callisto --fill
ts refuse orin-bot pr create -R castrog/thing --fill
ts refuse other pr create -R ghe.example.com/orin-dx/callisto --fill
ts refuse orin-bot pr create --web
ts refuse orin-bot pr create -dw
ts bot orin-bot pr create --title -h --fill
ts noauth orin-bot pr create --help
ts noauth other pr create -h
ts refuse other pr create --head orin-dx:feature --fill
GH_REAL=/tmp/evil PR_BOT_TOKEN_CMD=/tmp/evil PR_BOT_HELPER=/tmp/evil PR_BOT_CACHE=/tmp/evil ts bot orin-bot pr create --fill
if grep -qE '^(GH_REAL|PR_BOT_TOKEN_CMD|PR_BOT_HELPER|PR_BOT_CACHE)=' "$T/mint.env"; then
  record clean leaked "[shim] caller overrides reached the mint"
else
  record clean clean "[shim] caller overrides do not reach the mint"
fi
touch "$T/mint.fail"
ts refuse orin-bot pr create --fill

echo "pr-bot-guard tests: $PASS passed, $FAIL failed, $N total"
[[ -n $FAILS ]] && printf '%s\n' "$FAILS"
((FAIL == 0))
