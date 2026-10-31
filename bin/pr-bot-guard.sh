#!/bin/bash
# pr-bot-guard.sh: PreToolUse hook that keeps AI agents on the orin-dx-pr-bot path.
#
# Shared by Claude Code (Bash and file tools), Codex (hooks.json) and Antigravity (adapters/).
# Reads one hook payload on stdin. Understands:
#   Claude Code / Codex: {"tool_name":"Bash","tool_input":{"command":"..."},"cwd":"..."}
#                        (command may also be an argv array) and file tools ({"tool_input":{"file_path":..}})
#   Antigravity:         {"toolCall":{"name":"run_command","args":{"CommandLine":"...","Cwd":"..."}}}
# Allow: prints nothing, exit 0 (the agent's normal permission flow still applies).
# Deny:  prints a Claude-style deny JSON on stdout, the reason on stderr, exit 2.
# Anything unexpected (bad JSON, unparseable command, internal error) is a deny: this hook fails CLOSED.
#
# HONESTY NOTE: this is an advisory guardrail. It only sees the text of a tool call, so it cannot see
# what a script file, a variable built at runtime, or an interpreter (python/node) will do. The real
# boundaries are (1) the OS sandbox read-deny on the bot's key/cache dirs, (2) root-owned agent settings
# so an agent cannot remove this hook, and (3) GitHub rulesets / required reviews. See tests/guard/README.md.
#
# Rules (each is tested in tests/guard/run.sh):
#   R1 protected names/paths: the key, sealed store, token caches, signing helper, mint script, and any
#      path (after quote removal, ~/$HOME expansion, ../ normalisation, glob and brace matching) inside them.
#      Includes running `bash|sh|zsh|python|node <file>` on a file inside those dirs.
#   R2 recursive tools (grep -r, rg, find, tar, cp -r, ...) pointed at an ancestor of a protected dir.
#   R3 the real gh: absolute/Cellar paths, `command -p gh`, PATH=/export PATH/env -P/hash -p/alias gh,
#      copying the gh binary: any PR write or PR-endpoint API write through it is denied everywhere.
#   R4 `gh pr merge|review|ready|edit|close|reopen|update-branch|lock|unlock|revert` in orin-dx repos;
#      `gh pr create --web` in orin-dx repos; gh aliases/extensions (unknown subcommands) in orin-dx repos;
#      `gh alias set|import` anywhere.
#   R5 `gh api` writes to PR/review/merge endpoints of orin-dx repos; GraphQL mutations touching PRs,
#      reviews or merges anywhere (node ids hide the repo); GraphQL writes whose query cannot be read.
#   R6 curl/wget/httpie writes to api.github.com PR/review/merge endpoints of orin-dx repos and PR GraphQL.
#   R7 `entire trail link|create|merge|approve` in an orin-dx repo unless the current branch already has an
#      open PR authored by orin-dx-pr-bot (one read-only `gh pr list` call, ~0.5-2 s, 10 s timeout;
#      any failure denies).
#   R8 code the guard cannot see: dynamic command names, `eval`/`bash -c` of expanded text, and
#      `... | sh` are denied when the command is in an orin-dx repo or mentions gh/entire/the API.
#   R9 writes to the shim and agent hook configs (~/.local/bin/gh, ~/.claude/settings*.json,
#      ~/.codex/hooks.json|config.toml, ~/.gemini/).
#   R10 fail closed: invalid JSON, unterminated quotes/substitutions, too much nesting, internal errors.

# The tests substitute this one line to put a fake gh first; nothing in the environment can change it.
GUARD_PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin
PATH=$GUARD_PATH
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_CONFIG_PARAMETERS \
  GIT_CONFIG_COUNT GH_REPO GH_HOST GH_CONFIG_DIR 2>/dev/null
set -o pipefail
umask 077

GH_TIMEOUT=10
BOT_LOGIN_RE='^(app/)?orin-dx-pr-bot(\[bot\])?$'
DECIDED=0

json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/ }
  s=${s//$'\r'/ }
  REPLY=$s
}

deny() {
  DECIDED=1
  local msg="orin-dx PR-bot guard: $1"
  json_escape "$msg"
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$REPLY"
  printf '%s\n' "$msg" >&2
  exit 2
}

allow() {
  DECIDED=1
  exit 0
}

trap 'if [[ $DECIDED != 1 ]]; then deny "internal error in the guard; failing closed."; fi' EXIT

[[ -n ${HOME:-} && $HOME == /* ]] || deny "HOME is not set; failing closed."
HOME=${HOME%/}
USER_NAME=${HOME##*/}

# ---------------------------------------------------------------------------------------------------
# Protected locations
# ---------------------------------------------------------------------------------------------------
PROT_DIRS=(
  "$HOME/.config/orin-dx"
  "$HOME/.cache/orin-dx"
  "$HOME/Library/Application Support/OrinDX-PR-Bot"
  "$HOME/Library/Caches/OrinDX-PR-Bot"
  "$HOME/Applications/Orin DX PR Bot.app"
  "/Applications/Orin DX PR Bot.app"
)
PROT_FILES=(
  "$HOME/.config/orin-dx/pr-bot-token"
  "$HOME/.config/orin-dx/pr-bot-guard.sh"
  "$HOME/.config/orin-dx/pr-bot.pem.age"
  "$HOME/.config/orin-dx/pr-bot.se-identity"
  "$HOME/.config/orin-dx/pr-bot.se-recipient"
  "$HOME/Library/Caches/OrinDX-PR-Bot/jwt"
  "$HOME/Library/Caches/OrinDX-PR-Bot/installation-id"
  "$HOME/Applications/Orin DX PR Bot.app/Contents/MacOS/pr-bot-sign"
)
# Things an agent must not rewrite (the shim and the hook wiring). Reading them is fine.
TAMPER_DIRS=("$HOME/.gemini")
TAMPER_FILES=(
  "$HOME/.local/bin/gh"
  "$HOME/.claude/settings.json"
  "$HOME/.claude/settings.local.json"
  "$HOME/.codex/hooks.json"
  "$HOME/.codex/config.toml"
)
# Every ancestor of a protected dir: a recursive tool started here walks into the protected dir.
PROT_ANC=()
for _d in "${PROT_DIRS[@]}"; do
  _p=$_d
  while [[ $_p == */* && -n $_p ]]; do
    _p=${_p%/*}
    [[ -n $_p ]] || _p=/
    _seen=0
    for _a in "${PROT_ANC[@]}"; do [[ $_a == "$_p" ]] && _seen=1; done
    ((_seen)) || PROT_ANC+=("$_p")
    [[ $_p == / ]] && break
  done
done

NAME_RE='pr-bot-token|pr-bot-sign|pr-bot\.pem|pr-bot\.se-|\.config/orin-dx|\.cache/orin-dx|orindx-pr-bot|orin[[:space:]]+dx[[:space:]]+pr[[:space:]]+bot|age-plugin-se|(^|[^[:alnum:]_-])age[[:space:]]+(-[[:alpha:]]*d|--decrypt)'
SQUEEZE_RE='configorindx|cacheorindx|prbottoken|prbotsign|prbotpem|prbotse(identity|recipient)|agepluginse'
SENS_RE='(^|[^[:alnum:]_-])(gh|graphql|trail|entire|pulls)([^[:alnum:]_-]|$)|api\.github\.com'
ORIN_RE='(^|[/:@[:space:]=])orin-dx(/|:|$|[[:space:]])'
PR_EP_RE='(^|/)(pulls|merges)(/|$|[?])|/merge($|[?/])|/reviews|requested_reviewers|auto-?merge'
GH_GROUPS=" agent-task attestation auth browse cache co codespace completion config copilot gist gpg-key help issue label org preview project release repo ruleset run search secret ssh-key status variable workflow version accessibility alias api extension extensions ext pr "

# Case-insensitive regex match (macOS paths, GitHub owners, HTTP methods). BASH_REMATCH is kept.
imatch() {
  local rc
  shopt -s nocasematch
  [[ $1 =~ $2 ]]
  rc=$?
  shopt -u nocasematch
  return $rc
}

# ---------------------------------------------------------------------------------------------------
# Name and path matching
# ---------------------------------------------------------------------------------------------------
check_names() {
  local x=$1 sq
  if imatch "$x" "$NAME_RE"; then
    deny "the orin-dx-pr-bot key, token caches, signing helper and mint script are off limits to agents (matched '${BASH_REMATCH[0]}'). Use plain \`gh pr create\`, which handles them."
  fi
  sq=${x//[^[:alnum:]]/}
  if imatch "$sq" "$SQUEEZE_RE"; then
    deny "the orin-dx-pr-bot credentials are off limits to agents (obfuscated reference '${BASH_REMATCH[0]}'). Use plain \`gh pr create\`."
  fi
}

# Escape a literal string for use inside our glob patterns.
pesc() {
  local x=$1 out="" k ch
  case $x in
    *[\*\?\[\]\\\{\}]*)
      for ((k = 0; k < ${#x}; k++)); do
        ch=${x:k:1}
        case $ch in
          '*' | '?' | '[' | ']' | '\' | '{' | '}') out+="\\$ch" ;;
          *) out+=$ch ;;
        esac
      done
      REPLY=$out
      ;;
    *) REPLY=$x ;;
  esac
}

# One glob component -> ERE fragment.
c2re() {
  local c=$1 r="" k ch n=${#1} rest cls
  if [[ $c == '**' ]]; then REPLY='.*'; return; fi
  for ((k = 0; k < n; k++)); do
    ch=${c:k:1}
    case $ch in
      '\')
        k=$((k + 1))
        ch=${c:k:1}
        case $ch in
          '.' | '[' | ']' | '(' | ')' | '{' | '}' | '*' | '+' | '?' | '^' | '$' | '|' | '\') r+="\\$ch" ;;
          *) r+=$ch ;;
        esac
        ;;
      '*') r+='[^/]*' ;;
      '?') r+='[^/]' ;;
      '[')
        rest=${c:k+1}
        if [[ $rest == ?*']'* ]]; then
          cls=${rest:0:1}
          rest=${rest:1}
          cls+=${rest%%]*}
          k=$((k + ${#cls} + 1))
          [[ ${cls:0:1} == '!' ]] && cls="^${cls:1}"
          r+="[$cls]"
        else
          r+='\['
        fi
        ;;
      '.' | ']' | '(' | ')' | '{' | '}' | '+' | '^' | '$' | '|') r+="\\$ch" ;;
      *) r+=$ch ;;
    esac
  done
  REPLY=$r
}

# Normalise a pattern to absolute components in NC[] and their regexes in NRE[]; HAS_SS=1 if '**'.
norm_pat() {
  local p=$1 rest comp
  [[ $p == /* ]] || p="$VCWD_PAT/$p"
  NC=()
  rest=$p/
  while [[ -n $rest ]]; do
    comp=${rest%%/*}
    rest=${rest#*/}
    case $comp in
      '' | '.') ;;
      '..') ((${#NC[@]})) && unset "NC[$((${#NC[@]} - 1))]" ;;
      *) NC+=("$comp") ;;
    esac
  done
  NRE=()
  HAS_SS=0
  for comp in "${NC[@]}"; do
    c2re "$comp"
    NRE+=("$REPLY")
    [[ $comp == '**' ]] && HAS_SS=1
  done
}

re_join() { # first N of NRE -> anchored regex
  local n=$1 k r=""
  for ((k = 0; k < n; k++)); do r+="/${NRE[k]}"; done
  [[ -n $r ]] || r=/
  REPLY="^${r}\$"
}

depth() {
  local p=$1 d=0 rest=${1#/}
  [[ -n $rest ]] || { REPLY=0; return; }
  while [[ $rest == */* ]]; do
    d=$((d + 1))
    rest=${rest#*/}
  done
  REPLY=$((d + 1))
}

# Does the normalised pattern (NRE) point at or inside one of the given dirs, or at one of the files?
hits_list() { # usage: hits_list <ndirs> dirs... files...
  local rc
  shopt -s nocasematch
  _hits_list "$@"
  rc=$?
  shopt -u nocasematch
  return $rc
}
_hits_list() {
  local nd=$1 full j k P r
  local -a pre=()
  shift
  re_join ${#NRE[@]}
  full=$REPLY
  # Every prefix of the pattern that ends in a real component: if one equals a protected dir, the
  # pattern points inside it. (A prefix ending in '**' would match everything, so it is skipped.)
  for ((j = 1; j <= ${#NRE[@]}; j++)); do
    [[ ${NC[j - 1]} == '**' ]] && continue
    local lastlit=${NC[j - 1]//[\*\?]/}
    ((HAS_SS)) && [[ -z $lastlit ]] && continue
    re_join "$j"
    pre+=("$REPLY")
  done
  for ((k = 1; k <= $#; k++)); do
    P=${!k}
    [[ $P =~ $full ]] && return 0
    if ((k <= nd)); then
      for r in "${pre[@]}"; do [[ $P =~ $r ]] && return 0; done
    fi
  done
  return 1
}

prot_hit() { hits_list ${#PROT_DIRS[@]} "${PROT_DIRS[@]}" "${PROT_FILES[@]}"; }
tamper_hit() { hits_list ${#TAMPER_DIRS[@]} "${TAMPER_DIRS[@]}" "${TAMPER_FILES[@]}"; }
anc_hit() {
  local A full
  re_join ${#NRE[@]}
  full=$REPLY
  for A in "${PROT_ANC[@]}"; do imatch "$A" "$full" && return 0; done
  return 1
}

# Check a word (pattern form) for a protected path.
check_path_pat() {
  local pat=$1
  [[ -n $pat && $pat != *$'\n'* ]] || return 0
  norm_pat "$pat"
  if prot_hit; then
    deny "this touches the orin-dx-pr-bot key/token/helper directories (${pat//\\/}). Agents never read, list, copy or run anything there; use plain \`gh pr create\`."
  fi
}

# ---------------------------------------------------------------------------------------------------
# Tokenizer: a conservative POSIX-shell lexer. Produces parallel arrays
#   TW (text: quotes removed, ~/$HOME expanded, dynamic parts as \x01), TP (glob pattern form),
#   TK (w word, s separator, r redirection operator, h heredoc/herestring body), TD (dynamic), TG (glob).
# Command/process substitutions and backticks are queued in QUEUE and analysed as commands themselves.
# ---------------------------------------------------------------------------------------------------
_lit() {
  _cur+=$1
  pesc "$1"
  _pat+=$REPLY
  _inw=1
}
_dynmark() {
  _cur+=$'\x01'
  _pat+='*'
  _dyn=1
  _inw=1
}
_flush() {
  if ((_inw)); then
    if ((EXPECT_HD)); then
      HD_IDX+=(${#TW[@]})
      HD_DELIM+=("$_cur")
      HD_QUOTED+=("$HD_Q")
      HD_STRIP+=("$HD_S")
      TW+=("")
      TP+=("")
      TK+=(h)
      TD+=($((1 - HD_Q)))
      TG+=(0)
      EXPECT_HD=0
    else
      TW+=("$_cur")
      TP+=("$_pat")
      TK+=(w)
      TD+=("$_dyn")
      TG+=("$_glob")
    fi
  fi
  _cur=""
  _pat=""
  _inw=0
  _dyn=0
  _glob=0
}
_push() {
  TW+=("$2")
  TP+=("")
  TK+=("$1")
  TD+=(0)
  TG+=(0)
}

_match_paren() { # $1 string, $2 index just after '(' -> REPLY index of matching ')'
  local s=$1 j=$2 n=${#1} depth=1 ch rest k hs dl pd line cmp
  local -a pend=()
  while ((j < n)); do
    ch=${s:j:1}
    case $ch in
      '<')
        # Heredoc inside $( ): its body is data (apostrophes, parens), skip it at the next newline.
        if [[ ${s:j+1:1} == '<' && ${s:j+2:1} != '<' ]]; then
          k=$((j + 2))
          hs=0
          if [[ ${s:k:1} == '-' ]]; then
            hs=1
            k=$((k + 1))
          fi
          while [[ ${s:k:1} == ' ' || ${s:k:1} == $'\t' ]]; do k=$((k + 1)); done
          rest=${s:k}
          dl=${rest%%[[:space:]\;\|\&\)\<\>]*}
          if [[ -n $dl ]]; then
            k=$((k + ${#dl}))
            dl=${dl//[\'\"\\]/}
            pend+=("$hs:$dl")
          fi
          j=$k
          continue
        fi
        ;;
      $'\n')
        if ((${#pend[@]})); then
          j=$((j + 1))
          for pd in "${pend[@]}"; do
            hs=${pd%%:*}
            dl=${pd#*:}
            while ((j < n)); do
              rest=${s:j}
              if [[ $rest == *$'\n'* ]]; then line=${rest%%$'\n'*}; else line=$rest; fi
              j=$((j + ${#line} + 1))
              cmp=$line
              if [[ $hs == 1 ]]; then while [[ $cmp == $'\t'* ]]; do cmp=${cmp#?}; done; fi
              [[ $cmp == "$dl" ]] && break
            done
          done
          pend=()
          continue
        fi
        ;;
      '\')
        j=$((j + 2))
        continue
        ;;
      "'")
        rest=${s:j+1}
        [[ $rest == *"'"* ]] || return 1
        rest=${rest%%"'"*}
        j=$((j + ${#rest} + 2))
        continue
        ;;
      '"')
        j=$((j + 1))
        while ((j < n)); do
          ch=${s:j:1}
          if [[ $ch == '\' ]]; then
            j=$((j + 2))
            continue
          fi
          [[ $ch == '"' ]] && break
          j=$((j + 1))
        done
        ((j < n)) || return 1
        j=$((j + 1))
        continue
        ;;
      '(') depth=$((depth + 1)) ;;
      ')')
        depth=$((depth - 1))
        if ((depth == 0)); then
          REPLY=$j
          return 0
        fi
        ;;
    esac
    j=$((j + 1))
  done
  return 1
}

_tick() { # $1 string, $2 index of opening backtick
  local s=$1 j=$(($2 + 1)) n=${#1} ch
  while ((j < n)); do
    ch=${s:j:1}
    if [[ $ch == '\' ]]; then
      j=$((j + 2))
      continue
    fi
    [[ $ch == '`' ]] && break
    j=$((j + 1))
  done
  ((j < n)) || {
    PARSE_ERR="unterminated backtick"
    return 1
  }
  QUEUE+=("${s:$2+1:j-$2-1}")
  _dynmark
  REPLY=$((j + 1))
}

_ansic() { # decode the body of $'...' into REPLY; fail on escapes we cannot decode
  local c=$1 q="'" bs='\'
  case $c in *'\u'* | *'\U'* | *'\c'*) return 1 ;; esac
  c=${c//"$bs$q"/$q}
  c=${c//"$bs\""/\"}
  c=${c//"$bs?"/?}
  if [[ $c == *'\'* ]]; then
    c=$(printf '%s' "$c" | sed -E 's/\\([0-7]{1,3})/\\0\1/g') || return 1
    printf -v REPLY '%b' "$c"
  else
    REPLY=$c
  fi
}

_dollar() { # $1 string, $2 index of '$' -> REPLY next index
  local s=$1 p=$2 nx name rest
  nx=${s:p+1:1}
  case $nx in
    '(')
      if [[ ${s:p+2:1} == '(' ]]; then
        _match_paren "$s" $((p + 2)) || {
          PARSE_ERR="unbalanced \$(( ))"
          return 1
        }
        _dynmark
        REPLY=$((REPLY + 1))
        return 0
      fi
      _match_paren "$s" $((p + 2)) || {
        PARSE_ERR="unbalanced \$( )"
        return 1
      }
      QUEUE+=("${s:p+2:REPLY-p-2}")
      _dynmark
      REPLY=$((REPLY + 1))
      ;;
    '{')
      rest=${s:p+2}
      [[ $rest == *'}'* ]] || {
        PARSE_ERR="unterminated \${"
        return 1
      }
      name=${rest%%\}*}
      if [[ $name == HOME ]]; then
        _lit "$HOME"
      elif [[ $name == PWD ]] && ((VCWD_KNOWN)); then
        _lit "$VCWD"
      else
        case $name in *'$('* | *'`'*) QUEUE+=("${name#*[-=?+]}") ;; esac
        _dynmark
      fi
      REPLY=$((p + 3 + ${#name}))
      ;;
    [A-Za-z_])
      rest=${s:p+1}
      [[ $rest =~ ^([A-Za-z_][A-Za-z0-9_]*) ]]
      name=${BASH_REMATCH[1]}
      if [[ $name == HOME ]]; then
        _lit "$HOME"
      elif [[ $name == PWD ]] && ((VCWD_KNOWN)); then
        _lit "$VCWD"
      else
        _dynmark
      fi
      REPLY=$((p + 1 + ${#name}))
      ;;
    *)
      if [[ -n $nx && '@*#?$!-0123456789' == *"$nx"* ]]; then
        _dynmark
        REPLY=$((p + 2))
      else
        _lit '$'
        REPLY=$((p + 1))
      fi
      ;;
  esac
}

_read_heredocs() { # $1 string, $2 index just after the newline -> REPLY next index
  local s=$1 i=$2 n=${#1} k line body delim rest
  for k in "${!HD_IDX[@]}"; do
    body=""
    delim=${HD_DELIM[k]}
    while ((i < n)); do
      rest=${s:i}
      if [[ $rest == *$'\n'* ]]; then line=${rest%%$'\n'*}; else line=$rest; fi
      i=$((i + ${#line} + 1))
      local cmp=$line
      if [[ ${HD_STRIP[k]} == 1 ]]; then while [[ $cmp == $'\t'* ]]; do cmp=${cmp#?}; done; fi
      [[ $cmp == "$delim" ]] && break
      body+="$line"$'\n'
    done
    TW[${HD_IDX[k]}]=$body
    TD[${HD_IDX[k]}]=0
    if [[ ${HD_QUOTED[k]} != 1 && ( $body == *'$'* || $body == *'`'* ) ]]; then
      TD[${HD_IDX[k]}]=1
    fi
    if [[ ${HD_QUOTED[k]} != 1 ]]; then
      # Unquoted heredoc: $(...) and backticks inside run. Analyse them.
      _scan_subst "$body"
    fi
  done
  HD_IDX=()
  HD_DELIM=()
  HD_QUOTED=()
  HD_STRIP=()
  ((i > n)) && i=$n
  REPLY=$i
}

_scan_subst() { # queue $(...) and `...` found in unquoted heredoc text
  local s=$1 i=0 n=${#1} c
  while ((i < n)); do
    c=${s:i:1}
    if [[ $c == '\' ]]; then
      i=$((i + 2))
      continue
    fi
    if [[ $c == '$' && ${s:i+1:1} == '(' && ${s:i+2:1} != '(' ]]; then
      _match_paren "$s" $((i + 2)) || {
        PARSE_ERR="unbalanced \$( ) in heredoc"
        return 1
      }
      QUEUE+=("${s:i+2:REPLY-i-2}")
      i=$((REPLY + 1))
      continue
    fi
    if [[ $c == '`' ]]; then
      local j=$((i + 1))
      while ((j < n)) && [[ ${s:j:1} != '`' ]]; do j=$((j + 1)); done
      QUEUE+=("${s:i+1:j-i-1}")
      i=$((j + 1))
      continue
    fi
    i=$((i + 1))
  done
}

tokenize() {
  local s=$1 n=${#1} i=0 c nx j rest lit op name
  TW=()
  TP=()
  TK=()
  TD=()
  TG=()
  _cur=""
  _pat=""
  _inw=0
  _dyn=0
  _glob=0
  EXPECT_HD=0
  HD_Q=0
  HD_S=0
  HD_IDX=()
  HD_DELIM=()
  HD_QUOTED=()
  HD_STRIP=()
  PARSE_ERR=""
  while ((i < n)); do
    c=${s:i:1}
    case $c in
      "'")
        rest=${s:i+1}
        [[ $rest == *"'"* ]] || {
          PARSE_ERR="unterminated single quote"
          return 1
        }
        lit=${rest%%"'"*}
        _lit "$lit"
        ((EXPECT_HD)) && HD_Q=1
        i=$((i + ${#lit} + 2))
        ;;
      '"')
        ((EXPECT_HD)) && HD_Q=1
        _inw=1
        j=$((i + 1))
        while :; do
          ((j < n)) || {
            PARSE_ERR="unterminated double quote"
            return 1
          }
          c=${s:j:1}
          case $c in
            '"')
              j=$((j + 1))
              break
              ;;
            '\')
              nx=${s:j+1:1}
              case $nx in
                '$' | '`' | '"' | '\') _lit "$nx"; j=$((j + 2)) ;;
                $'\n') j=$((j + 2)) ;;
                *) _lit '\'; j=$((j + 1)) ;;
              esac
              ;;
            '$')
              _dollar "$s" "$j" || return 1
              j=$REPLY
              ;;
            '`')
              _tick "$s" "$j" || return 1
              j=$REPLY
              ;;
            *)
              # Copy a run of ordinary characters at once.
              rest=${s:j}
              lit=${rest%%[\"\\\$\`]*}
              _lit "$lit"
              j=$((j + ${#lit}))
              ;;
          esac
        done
        i=$j
        ;;
      '\')
        nx=${s:i+1:1}
        if [[ $nx == $'\n' ]]; then
          i=$((i + 2))
          continue
        fi
        if [[ -n $nx ]]; then _lit "$nx"; else _lit '\'; fi
        ((EXPECT_HD)) && HD_Q=1
        i=$((i + 2))
        ;;
      '$')
        nx=${s:i+1:1}
        if [[ $nx == "'" ]]; then
          j=$((i + 2))
          while ((j < n)); do
            c=${s:j:1}
            if [[ $c == '\' ]]; then
              j=$((j + 2))
              continue
            fi
            [[ $c == "'" ]] && break
            j=$((j + 1))
          done
          ((j < n)) || {
            PARSE_ERR="unterminated \$'...'"
            return 1
          }
          lit=${s:i+2:j-i-2}
          if _ansic "$lit"; then _lit "$REPLY"; else _dynmark; fi
          ((EXPECT_HD)) && HD_Q=1
          i=$((j + 1))
        elif [[ $nx == '"' ]]; then
          i=$((i + 1))
        else
          _dollar "$s" "$i" || return 1
          i=$REPLY
        fi
        ;;
      '`')
        _tick "$s" "$i" || return 1
        i=$REPLY
        ;;
      ' ' | $'\t' | $'\r')
        _flush
        i=$((i + 1))
        ;;
      $'\n' | ';')
        _flush
        _push s "$c"
        i=$((i + 1))
        if [[ $c == $'\n' ]] && ((${#HD_IDX[@]})); then
          _read_heredocs "$s" "$i" || return 1
          i=$REPLY
        fi
        ;;
      '&' | '|')
        nx=${s:i+1:1}
        _flush
        if [[ $c == '&' && $nx == '>' ]]; then
          i=$((i + 2))
          op='&>'
          if [[ ${s:i:1} == '>' ]]; then
            op='&>>'
            i=$((i + 1))
          fi
          _push r "$op"
        else
          _push s "$c"
          i=$((i + 1))
          [[ $nx == '&' || $nx == '|' ]] && i=$((i + 1))
        fi
        ;;
      '(' | ')')
        _flush
        _push s "$c"
        i=$((i + 1))
        ;;
      '<' | '>')
        if ((_inw && !_dyn)) && [[ $_cur =~ ^[0-9]+$ ]]; then
          _cur=""
          _pat=""
          _inw=0
        fi
        _flush
        nx=${s:i+1:1}
        if [[ $nx == '(' ]]; then
          _match_paren "$s" $((i + 2)) || {
            PARSE_ERR="unbalanced process substitution"
            return 1
          }
          QUEUE+=("${s:i+2:REPLY-i-2}")
          _dynmark
          i=$((REPLY + 1))
          continue
        fi
        op=$c
        j=$((i + 1))
        if [[ $c == '<' ]]; then
          if [[ ${s:j:2} == '<<' ]]; then
            op='<<<'
            j=$((j + 2))
          elif [[ ${s:j:1} == '<' ]]; then
            op='<<'
            j=$((j + 1))
            if [[ ${s:j:1} == '-' ]]; then
              op='<<-'
              j=$((j + 1))
            fi
          elif [[ ${s:j:1} == '&' || ${s:j:1} == '>' ]]; then
            op+=${s:j:1}
            j=$((j + 1))
          fi
        else
          case ${s:j:1} in
            '>' | '|' | '&')
              op+=${s:j:1}
              j=$((j + 1))
              ;;
          esac
        fi
        _push r "$op"
        i=$j
        if [[ $op == '<<' || $op == '<<-' ]]; then
          EXPECT_HD=1
          HD_Q=0
          HD_S=0
          [[ $op == '<<-' ]] && HD_S=1
        fi
        ;;
      '#')
        if ((_inw)); then
          _lit '#'
          i=$((i + 1))
        else
          rest=${s:i}
          [[ $rest == *$'\n'* ]] && rest=${rest%%$'\n'*}
          i=$((i + ${#rest}))
        fi
        ;;
      '~')
        if ((!_inw)) || [[ $_cur == *= || $_cur == *: ]]; then
          rest=${s:i+1}
          [[ $rest =~ ^([A-Za-z0-9._-]*) ]]
          name=${BASH_REMATCH[1]}
          if [[ -z $name || $name == "$USER_NAME" ]]; then
            _lit "$HOME"
          else
            _lit "/Users/$name"
          fi
          i=$((i + 1 + ${#name}))
        else
          _lit '~'
          i=$((i + 1))
        fi
        ;;
      '*' | '?' | '[' | ']')
        if [[ $c == '[' ]] && ((!_inw)) && [[ ${s:i+1:1} == ' ' || ${s:i+1:1} == '[' ]]; then
          _lit '['
        else
          _cur+=$c
          _pat+=$c
          _glob=1
          _inw=1
        fi
        i=$((i + 1))
        ;;
      '{')
        rest=${s:i+1}
        lit=${rest%%\}*}
        if [[ $rest == *'}'* && $lit != *[[:space:]\'\"\$]* ]] && [[ $lit == *,* || $lit == *..* ]]; then
          _cur+="{$lit}"
          _pat+='*'
          _glob=1
          _inw=1
          i=$((i + ${#lit} + 2))
        else
          _lit '{'
          i=$((i + 1))
        fi
        ;;
      *)
        rest=${s:i}
        lit=${rest%%[\'\"\\\$\`[:space:]\;\&\|\(\)\<\>\#\~\*\?\[\]\{]*}
        [[ -n $lit ]] || lit=$c
        _lit "$lit"
        i=$((i + ${#lit}))
        ;;
    esac
  done
  _flush
  return 0
}

# ---------------------------------------------------------------------------------------------------
# Repo context
# ---------------------------------------------------------------------------------------------------
ORIN_CACHE_DIR=""
ORIN_CACHE_VAL=""
ORIN_NWO=""
is_orin_dir() { # $1 dir -> 0 if any remote points at github.com/orin-dx/*, sets ORIN_NWO
  local dir=$1 line url owner name
  if [[ $dir == "$ORIN_CACHE_DIR" && -n $ORIN_CACHE_VAL ]]; then
    [[ $ORIN_CACHE_VAL == yes ]]
    return
  fi
  ORIN_CACHE_DIR=$dir
  ORIN_CACHE_VAL=no
  ORIN_NWO=""
  [[ -d $dir ]] || return 1
  while IFS= read -r line; do
    url=${line#*[[:space:]]}
    url=${url%% *}
    url=${url%/}
    url=${url%.git}
    if [[ $url =~ [:/]([^/:]+)/([^/:]+)$ ]]; then
      owner=${BASH_REMATCH[1]}
      name=${BASH_REMATCH[2]}
      if imatch "$owner" '^orin-dx$'; then
        ORIN_CACHE_VAL=yes
        ORIN_NWO="orin-dx/$name"
        return 0
      fi
    fi
  done < <(git -C "$dir" remote -v 2>/dev/null)
  return 1
}

orin_here() {
  local d=${SEG_DIR:-$VCWD}
  ((VCWD_KNOWN)) || [[ -n $SEG_DIR ]] || return 0
  is_orin_dir "$d"
}

# Does the open PR for <branch> in <owner/repo> belong to the bot? 0 yes, 1 no, 2 could not tell.
check_bot_pr() {
  local nwo=$1 branch=$2 tmp pid wd rc out line
  tmp=$(mktemp "${TMPDIR:-/tmp}/prbotguard.XXXXXX") || return 2
  (GH_PROMPT_DISABLED=1 NO_COLOR=1 exec gh pr list -R "$nwo" --head "$branch" --state open \
    --json author --jq '.[].author.login' </dev/null >"$tmp" 2>/dev/null) &
  pid=$!
  (
    sleep "$GH_TIMEOUT"
    kill -9 "$pid"
  ) >/dev/null 2>&1 &
  wd=$!
  { wait "$pid"; } 2>/dev/null
  rc=$?
  pkill -P "$wd" >/dev/null 2>&1
  kill "$wd" >/dev/null 2>&1
  { wait "$wd"; } 2>/dev/null
  out=$(<"$tmp")
  rm -f "$tmp"
  ((rc == 0)) || return 2
  while IFS= read -r line; do
    imatch "$line" "$BOT_LOGIN_RE" && return 0
  done <<<"$out"
  return 1
}

# ---------------------------------------------------------------------------------------------------
# Command analysis
# ---------------------------------------------------------------------------------------------------
dynamic_code() { # $1 what
  if orin_here || [[ $CMD_SENSITIVE == 1 ]]; then
    deny "$1 hides the real command from this guard, so it is blocked in orin-dx repos and around gh/entire/GitHub API calls. Run the command directly."
  fi
}

set_assign() { # $1 name, $2 token index, $3 global(1)/segment(0)
  local name=$1 k=$2 global=$3 val=${TW[$2]#*=}
  case $name in
    PATH | HOME | BASH_ENV | ENV | GH_PATH)
      if ((global)); then PATH_TAMPERED=1; else SEG_PATH=1; fi
      ;;
    GH_REPO)
      if ((global)); then
        GLOBAL_REPO=$val
        GLOBAL_REPO_DYN=${TD[k]}
      else
        SEG_REPO=$val
        SEG_REPO_DYN=${TD[k]}
      fi
      ;;
    GIT_DIR | GIT_WORK_TREE)
      if ((global)); then GLOBAL_GITDIR=1; else SEG_GITDIR=1; fi
      ;;
  esac
}

# Is this word a GitHub owner/repo reference to orin-dx?
mentions_orin() { imatch "$1" "$ORIN_RE" || imatch "$1" '^orin-dx$'; }

analyze_gh() { # $1 first arg position in SEGW, $2 end, $3 real(0/1)
  local q=$1 e=$2 real=$3 k w d expect=0 group="" gdyn=0 verb="" vdyn=0 orin=0 posdyn=0 web=0 haverepo=0 i
  ((SEG_PATH || PATH_TAMPERED)) && real=1
  local -a pos=()
  for ((i = q; i < e; i++)); do
    k=${SEGW[i]}
    w=${TW[k]}
    d=${TD[k]}
    mentions_orin "$w" && orin=1
    if ((expect)); then
      haverepo=1
      expect=0
      if ((d)) || [[ $w != */* ]] || mentions_orin "$w"; then orin=1; fi
      continue
    fi
    case $w in
      -R | --repo)
        expect=1
        continue
        ;;
      --repo=* | -R?*)
        haverepo=1
        w=${w#--repo=}
        w=${w#-R}
        w=${w#=}
        if ((d)) || [[ $w != */* ]] || mentions_orin "$w"; then orin=1; fi
        continue
        ;;
      --web) web=1 ;;
    esac
    if [[ $w == -* ]]; then
      if [[ $w =~ ^-[a-zA-Z]+$ ]]; then
        local fl=${w#-} c2 x
        for ((x = 0; x < ${#fl}; x++)); do
          c2=${fl:x:1}
          [[ $c2 == w ]] && {
            web=1
            break
          }
          case $c2 in a | B | b | F | H | l | m | p | r | t | T | R | q | X | f) break ;; esac
        done
      fi
      continue
    fi
    if [[ -z $group ]]; then
      group=$w
      gdyn=$d
      GH_GI=$i
      continue
    fi
    if [[ -z $verb ]]; then
      verb=$w
      vdyn=$d
      continue
    fi
    pos+=("$w")
    ((d)) && posdyn=1
  done
  ((expect)) && orin=1
  if ((!haverepo)); then
    local r=${SEG_REPO:-$GLOBAL_REPO} rd=$((SEG_REPO_DYN || GLOBAL_REPO_DYN))
    if [[ -n $r ]] || ((rd)); then
      if ((rd)) || [[ $r != */* ]] || mentions_orin "$r"; then orin=1; fi
    else
      orin_here && orin=1
    fi
  fi
  GH_ORIN=$orin

  if ((gdyn)); then
    ((real || orin)) && deny "a gh subcommand built at runtime cannot be checked here (real gh or orin-dx repo). Spell the command out."
    return 0
  fi
  [[ -n $group ]] || return 0
  case $group in
    pr)
      if ((vdyn)); then
        ((real || orin || posdyn)) && deny "a \`gh pr\` subcommand built at runtime cannot be checked in an orin-dx repo. Spell the command out."
        return 0
      fi
      case $verb in
        create | new)
          ((real)) && deny "open PRs with plain \`gh pr create\`: the gh shim runs it as orin-dx-pr-bot. The real gh binary (absolute or Cellar path, \`command -p\`, a changed PATH, an alias or env -P) would open the PR as you."
          ((orin && web)) && deny "\`gh pr create --web\` opens the PR in your browser as you. Drop --web; the shim opens it as orin-dx-pr-bot."
          ;;
        merge | review | ready | edit | close | reopen | update-branch | lock | unlock | revert)
          if ((real || orin || posdyn)); then
            deny "\`gh pr $verb\` acts as you, and in orin-dx repos reviewing, readying, editing, closing and merging PRs is for a human. Ask the user to do it."
          fi
          ;;
      esac
      ;;
    api) analyze_gh_api "$((GH_GI + 1))" "$e" "$real" "$orin" ;;
    alias)
      case $verb in set | import)
        deny "defining gh aliases is blocked: an alias can hide \`pr merge\` or \`api\` calls from this guard." ;;
      esac
      ;;
    extension | extensions | ext)
      case $verb in install | exec | upgrade | create)
        ((orin || real)) && deny "gh extensions run with your login; not allowed from an agent in orin-dx repos." ;;
      esac
      ;;
    *)
      if [[ $GH_GROUPS != *" $group "* ]]; then
        ((orin || real)) && deny "\`gh $group\` is not a built-in gh command (an alias or extension). Those run with your login and can hide PR writes, so they are blocked in orin-dx repos. Use the full built-in command."
      fi
      ;;
  esac
  return 0
}

analyze_gh_api() { # $1 start, $2 end, $3 real, $4 orin-context
  local q=$1 e=$2 real=$3 orin=$4 i k w d expect="" method="" mdyn=0 fields=0 input=0 endpoint="" edyn=0 qdyn=0 haveq=0 qtext=""
  for ((i = q; i < e; i++)); do
    k=${SEGW[i]}
    w=${TW[k]}
    d=${TD[k]}
    if [[ -n $expect ]]; then
      case $expect in
        method)
          method=$w
          mdyn=$d
          ;;
        field)
          fields=1
          if [[ $w == query=* ]]; then
            haveq=1
            qtext+=" $w"
            ((d)) && qdyn=1
            [[ $w == query=@* ]] && qdyn=1
          fi
          ;;
        input)
          input=1
          ;;
      esac
      expect=""
      continue
    fi
    case $w in
      -X | --method) expect=method ;;
      -X?* | --method=*)
        method=${w#--method=}
        method=${method#-X}
        method=${method#=}
        mdyn=$d
        ;;
      -f | -F | --field | --raw-field) expect=field ;;
      -f?* | -F?* | --field=* | --raw-field=*)
        fields=1
        w=${w#--field=}
        w=${w#--raw-field=}
        w=${w#-[fF]}
        if [[ $w == query=* ]]; then
          haveq=1
          qtext+=" $w"
          ((d)) && qdyn=1
          [[ $w == query=@* ]] && qdyn=1
        fi
        ;;
      --input) expect=input ;;
      --input=*) input=1 ;;
      -H | --header | -q | --jq | -t | --template | --hostname | -p | --preview | --cache) expect=skip ;;
      -*) ;;
      *)
        if [[ -z $endpoint ]]; then
          endpoint=$w
          edyn=$d
        fi
        ;;
    esac
  done
  local write=0
  if [[ -n $method ]] || ((mdyn)); then
    if ((mdyn)) || ! imatch "$method" '^(GET|HEAD)$'; then write=1; fi
  elif ((fields || input)); then
    write=1
  fi
  ((write)) || return 0
  ((edyn)) && deny "a \`gh api\` write to an endpoint built at runtime cannot be checked. Spell out the endpoint (and use \`gh pr create\` for PRs)."
  if [[ $endpoint == graphql || $endpoint == */graphql ]]; then
    if ((input || qdyn || !haveq)); then
      deny "a GraphQL write whose query this guard cannot read (--input, @file or variables) is blocked: it could merge, review or open PRs."
    fi
    if imatch "$qtext" 'mutation'; then
      if imatch "$qtext" 'pullrequest|review|merge|automerge' || ((real)); then
        deny "GraphQL mutations on pull requests, reviews or merges are blocked for agents (node ids hide which repo they hit). Use \`gh pr create\` to open PRs; reviews and merges are for a human."
      fi
    fi
    return 0
  fi
  if imatch "$endpoint" "$PR_EP_RE" || imatch "$endpoint" '(^|/)repositories/'; then
    local owner=""
    if [[ $endpoint =~ (^|/)repos/([^/]+)/ ]]; then owner=${BASH_REMATCH[2]}; fi
    if ((real)) || imatch "$owner" '^orin-dx$' || imatch "$endpoint" '(^|/)repositories/' || [[ -z $owner ]] \
      || { [[ $owner == '{owner}' ]] && ((orin)); }; then
      deny "\`gh api\` writes to pull request, review or merge endpoints are blocked here. Open PRs with plain \`gh pr create\`; reviews and merges are for a human."
    fi
  fi
  return 0
}

analyze_entire() { # $1 first arg position, $2 end
  local q=$1 e=$2 i k w d w1="" w2="" gated=0 orin=0 dir branch rc
  for ((i = q; i < e; i++)); do
    k=${SEGW[i]}
    w=${TW[k]}
    d=${TD[k]}
    mentions_orin "$w" && orin=1
    [[ $w == -* ]] && continue
    if [[ -z $w1 ]]; then
      w1=$w
      if ((d)); then gated=1; fi
      continue
    fi
    if [[ -z $w2 && $w1 == trail ]]; then
      w2=$w
      if ((d)); then gated=1; fi
      case $w2 in link | create | merge | approve) gated=1 ;; esac
    fi
  done
  ((gated)) || return 0
  dir=${SEG_DIR:-$VCWD}
  if ((!VCWD_KNOWN)) && [[ -z $SEG_DIR ]]; then
    deny "cannot tell which repo \`entire trail\` would run in (dynamic cd). Run it from the repo directory without cd."
  fi
  is_orin_dir "$dir" && orin=1
  ((orin)) || return 0
  ((SEG_GITDIR || GLOBAL_GITDIR)) && deny "GIT_DIR/GIT_WORK_TREE with \`entire trail\` is blocked in orin-dx repos."
  is_orin_dir "$dir" || deny "\`entire trail $w2\` names an orin-dx repo that is not the current checkout; run it from that checkout."
  branch=$(git -C "$dir" symbolic-ref --short -q HEAD 2>/dev/null) || branch=""
  [[ -n $branch ]] || deny "could not determine the current branch for \`entire trail\` (detached HEAD?); failing closed."
  check_bot_pr "$ORIN_NWO" "$branch"
  rc=$?
  case $rc in
    0) return 0 ;;
    1) deny "\`entire ${w1//$'\x01'/\$VAR} ${w2//$'\x01'/\$VAR}\` opens or acts on the PR with your own GitHub login. Branch '$branch' has no open PR by orin-dx-pr-bot yet: open it first with plain \`gh pr create\` (the shim runs it as the bot), then link the trail." ;;
    *) deny "could not confirm that branch '$branch' already has an orin-dx-pr-bot PR (gh pr list failed or timed out); failing closed. Open the PR with plain \`gh pr create\` first." ;;
  esac
}

analyze_http() { # $1 first arg position, $2 end, $3 tool basename
  local q=$1 e=$2 tool=$3 i k w d expect="" method="" mdyn=0 write=0 get=0 cfg=0 urlgh=0 urldyn=0 data="" datadyn=0 anyurl=0 urls=""
  for ((i = q; i < e; i++)); do
    k=${SEGW[i]}
    w=${TW[k]}
    d=${TD[k]}
    if [[ -n $expect ]]; then
      case $expect in
        method)
          method=$w
          mdyn=$d
          ;;
        data)
          write=1
          data+=" $w"
          ((d)) && datadyn=1
          [[ $w == @* ]] && datadyn=1
          ;;
        cfg) cfg=1 ;;
      esac
      expect=""
      continue
    fi
    case $tool in
      curl | curlie)
        case $w in
          -X | --request) expect=method; continue ;;
          -X?* | --request=*)
            method=${w#--request=}
            method=${method#-X}
            mdyn=$d
            continue
            ;;
          -d | --data | --data-* | --json | -F | --form | --form-string | -T | --upload-file) expect=data; continue ;;
          -d?* | --data=* | --data-*=* | --json=* | -F?* | --form=* | -T?*)
            write=1
            data+=" $w"
            ((d)) && datadyn=1
            [[ $w == *@* ]] && datadyn=1
            continue
            ;;
          -G | --get) get=1; continue ;;
          -K | --config) expect=cfg; continue ;;
          -K?* | --config=*) cfg=1; continue ;;
          -H | --header | -u | --user | -o | --output | -A | --user-agent | -e | --referer | -b | --cookie | -c | --cookie-jar | -w | --write-out | -m | --max-time | --connect-timeout | -x | --proxy | -E | --cert | --cacert | --key)
            expect=skip
            continue
            ;;
        esac
        ;;
      wget)
        case $w in
          --method) expect=method; continue ;;
          --method=*)
            method=${w#--method=}
            mdyn=$d
            continue
            ;;
          --post-data | --post-file | --body-data | --body-file) expect=data; continue ;;
          --post-data=* | --post-file=* | --body-data=* | --body-file=*)
            write=1
            data+=" $w"
            ((d)) && datadyn=1
            [[ $w == --*-file=* ]] && datadyn=1
            continue
            ;;
          -e | --execute | -i | --input-file) expect=cfg; continue ;;
        esac
        ;;
      *) # httpie / xh
        if [[ -z $urls ]] && imatch "$w" '^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$'; then
          method=$w
          continue
        fi
        case $w in
          -f | --form) write=1 ;;
        esac
        if [[ -n $urls && $w != -* ]]; then
          if [[ $w =~ ^[^:=]+(:=|=|@) && $w != *==* ]]; then
            write=1
            data+=" $w"
            ((d)) && datadyn=1
          fi
        fi
        ;;
    esac
    [[ $w == -* ]] && continue
    if [[ $w == *://* || ($tool != curl && $tool != wget && -z $urls) ]] || imatch "$w" 'api\.github\.com'; then
      anyurl=1
      urls+=" $w"
      ((d)) && urldyn=1
      imatch "$w" 'api\.github\.com|/api/v3/|/api/graphql' && urlgh=1
    fi
  done
  ((anyurl)) || {
    # No URL we can see: a URL in a variable.
    for ((i = q; i < e; i++)); do ((TD[SEGW[i]])) && urldyn=1; done
  }
  if [[ -n $method ]] || ((mdyn)); then
    if ((mdyn)) || ! imatch "$method" '^(GET|HEAD)$'; then write=1; else write=0; fi
  elif ((get)); then
    write=0
  fi
  if ((cfg)); then
    if ((urlgh || urldyn)) || orin_here || [[ $CMD_SENSITIVE == 1 ]]; then
      deny "\`$tool\` with a config/input file hides the URL and method from this guard; not allowed for GitHub API calls or in orin-dx repos."
    fi
  fi
  ((write)) || return 0
  if ((urlgh)); then
    if imatch "$urls" 'graphql'; then
      if ((datadyn)) || imatch "$data" 'pullrequest|review|merge|automerge'; then
        deny "GraphQL writes to GitHub that touch pull requests, reviews or merges (or whose body is in a file/variable) are blocked for agents. Use \`gh pr create\` to open PRs."
      fi
      return 0
    fi
    if imatch "$urls" "$PR_EP_RE" || imatch "$urls" '/repositories/'; then
      if imatch "$urls" '/repos/orin-dx/|/repositories/' || ((urldyn)); then
        deny "direct GitHub API writes to orin-dx pull request, review or merge endpoints are blocked. Open PRs with plain \`gh pr create\`; reviews and merges are for a human."
      fi
    fi
    return 0
  fi
  if ((urldyn)); then
    if orin_here || [[ $CMD_SENSITIVE == 1 ]]; then
      deny "an HTTP write to a URL built at runtime cannot be checked in an orin-dx repo. Spell out the URL."
    fi
  fi
  return 0
}

analyze_shell() { # $1 position of the shell word, $2 end
  local q=$(($1 + 1)) e=$2 w k cflag=0 sflag=0 h
  while ((q < e)); do
    k=${SEGW[q]}
    w=${TW[k]}
    case $w in
      --)
        q=$((q + 1))
        break
        ;;
      -o | -O | +o | +O | --rcfile | --init-file) q=$((q + 2)) ;;
      --*) q=$((q + 1)) ;;
      -* | +*)
        [[ $w == -*c* ]] && cflag=1
        [[ $w == -*s* ]] && sflag=1
        q=$((q + 1))
        ;;
      *) break ;;
    esac
  done
  # -s: commands come from stdin; the remaining words are only positional parameters.
  ((sflag && !cflag)) && q=$e
  if ((cflag)); then
    ((q < e)) || deny "\`sh -c\` without a command; failing closed."
    k=${SEGW[q]}
    if ((TD[k])); then
      dynamic_code "\`${TW[${SEGW[$1]}]##*/} -c\` with expanded text"
    else
      QUEUE+=("${TW[k]}")
    fi
    return 0
  fi
  if ((q < e)); then
    k=${SEGW[q]}
    if ((TD[k])); then
      dynamic_code "running a script whose path is built at runtime"
      return 0
    fi
    norm_pat "${TP[k]}"
    prot_hit && deny "executing a script from the orin-dx-pr-bot directories is blocked."
    return 0
  fi
  # No -c, no script: the shell reads code from stdin.
  for h in "${SEGH[@]}"; do
    if ((TD[h])); then
      dynamic_code "a heredoc with expansions fed to a shell"
    else
      QUEUE+=("${TW[h]}")
    fi
  done
  ((${#SEGH[@]})) && return 0
  ((PIPED_IN || SEG_STDIN)) && dynamic_code "piping generated text into a shell"
  return 0
}

is_writer() {
  case $1 in
    cp | mv | rm | ln | install | tee | sed | gsed | perl | chmod | chown | chflags | truncate | dd | rsync | ditto | unlink | touch | xattr | vim | vi | nvim | nano | emacs | code | open | defaults | plutil | sponge | rmdir | mkdir | patch | python | python3 | node | ruby | osascript | yq | awk | gawk | ex | ed | tar | unzip | curl | wget) return 0 ;;
  esac
  return 1
}

is_recursive() { # $1 base, $2 start, $3 end
  local b=$1 i w
  case $b in
    rg | ag | ack | ugrep | fd | fdfind | find | tree | du | tar | gtar | bsdtar | zip | 7z | 7zz | rsync | ditto | mdfind | locate | fzf) return 0 ;;
    grep | egrep | fgrep | ggrep | cp | gcp | scp | ls | gls | chmod | chown | rm)
      local letters
      case $b in
        grep | egrep | fgrep | ggrep | rm) letters='rR' ;;
        cp | gcp | scp) letters='rRa' ;;
        *) letters='R' ;;
      esac
      for ((i = $2; i < $3; i++)); do
        w=${TW[${SEGW[i]}]}
        case $w in
          --recursive | --dereference-recursive | --directories=recurse | --archive) return 0 ;;
          --*) ;;
          -*["$letters"]*) return 0 ;;
        esac
      done
      ;;
  esac
  return 1
}

analyze_generic() { # $1 command position, $2 end, $3 base
  local p=$1 e=$2 base=$3 i k w npaths=0
  # R9: writes to the shim / hook configs
  if is_writer "$base"; then
    for ((i = p + 1; i < e; i++)); do
      k=${SEGW[i]}
      [[ ${TW[k]} == -* && ${TW[k]} != *=* ]] && continue
      w=${TP[k]}
      [[ ${TW[k]} == *=* ]] && w=${w#*=}
      norm_pat "$w"
      if tamper_hit; then
        case $base in cat | less | head | tail | grep | jq | diff) ;; *)
          deny "agents may not modify the gh shim or the agent hook settings (${TW[k]})." ;;
        esac
      fi
    done
  fi
  # R3: copying or linking the real gh binary under another name
  case $base in
    cp | ln | install | rsync | ditto | mv)
      for ((i = p + 1; i < e; i++)); do
        w=${TW[${SEGW[i]}]}
        if imatch "$w" '(^|/)Cellar/gh(/|$)|/bin/gh$' && [[ $w != "$HOME/.local/bin/gh" ]]; then
          deny "copying or linking the real gh binary is blocked: it would bypass the orin-dx gh shim."
        fi
      done
      ;;
  esac
  # R2: recursive tools at an ancestor of the protected dirs
  if is_recursive "$base" $((p + 1)) "$e"; then
    for ((i = p + 1; i < e; i++)); do
      k=${SEGW[i]}
      w=${TW[k]}
      [[ $w == -* ]] && continue
      ((TD[k])) && [[ ${w//$'\x01'/} != */* ]] && continue
      [[ $w == */* || $w == . || $w == .. || ${TG[k]} == 1 ]] || continue
      npaths=$((npaths + 1))
      norm_pat "${TP[k]}"
      if anc_hit; then
        deny "\`$base\` over ${w//$'\x01'/\$VAR} would walk into the orin-dx-pr-bot key/token directories. Point it at a narrower directory."
      fi
    done
    if ((npaths == 0)); then
      case $base in rg | ag | ack | ugrep | fd | fdfind | find | tree | du | grep | egrep | fgrep | ggrep)
        if ((VCWD_KNOWN)); then
          norm_pat "$VCWD_PAT"
          anc_hit && deny "\`$base\` from $VCWD would walk into the orin-dx-pr-bot key/token directories. Point it at a narrower directory."
        fi
        ;;
      esac
    fi
  fi
  # find -exec / -execdir / -ok: analyse the embedded command
  if [[ $base == find ]]; then
    for ((i = p + 1; i < e; i++)); do
      w=${TW[${SEGW[i]}]}
      case $w in -exec | -execdir | -ok | -okdir)
        local j=$((i + 1))
        while ((j < e)) && [[ ${TW[${SEGW[j]}]} != ';' && ${TW[${SEGW[j]}]} != '+' ]]; do j=$((j + 1)); done
        ((j > i + 1)) && run_cmd $((i + 1)) "$j"
        i=$j
        ;;
      esac
    done
    return 0
  fi
  case $base in echo | printf | man | which | type | whereis | tldr | git | grep | egrep | rg | ag | cat | less | head | tail | sed | awk | jq) return 0 ;; esac
  # A later word that is gh / entire (parallel, watch, script, unknown wrappers)
  for ((i = p + 1; i < e; i++)); do
    k=${SEGW[i]}
    w=${TW[k]}
    case ${w##*/} in
      gh)
        local r=0
        [[ $w == */* && $w != "$HOME/.local/bin/gh" ]] && r=1
        analyze_gh $((i + 1)) "$e" "$r"
        return 0
        ;;
      entire)
        analyze_entire $((i + 1)) "$e"
        return 0
        ;;
    esac
  done
  # A renamed or symlinked gh: `<something> pr merge ...` / `<something> api ...`
  local a1="" a2="" a1i=0
  for ((i = p + 1; i < e; i++)); do
    w=${TW[${SEGW[i]}]}
    [[ $w == -* ]] && continue
    if [[ -z $a1 ]]; then
      a1=$w
      a1i=$i
    elif [[ -z $a2 ]]; then
      a2=$w
      break
    fi
  done
  if [[ $a1 == pr && $a2 =~ ^(create|new|merge|review|ready|edit|close|reopen|update-branch)$ ]] || [[ $a1 == api ]]; then
    analyze_gh "$a1i" "$e" 1
  fi
  return 0
}

do_cd() { # $1 position after cd, $2 end
  local q=$1 e=$2 k w
  while ((q < e)) && [[ ${TW[${SEGW[q]}]} == -[LPe@]* ]]; do q=$((q + 1)); done
  if ((q >= e)); then
    VCWD=$HOME
  else
    k=${SEGW[q]}
    w=${TW[k]}
    if ((TD[k] || TG[k])) || [[ $w == - ]]; then
      VCWD_KNOWN=0
      return 0
    fi
    [[ $w == /* ]] || w="$VCWD/$w"
    pesc "$w"
    norm_pat "$REPLY"
    local out="" c
    for c in "${NC[@]}"; do out+="/$c"; done
    VCWD=${out:-/}
    VCWD=${VCWD//\\/}
  fi
  VCWD_KNOWN=1
  pesc "$VCWD"
  VCWD_PAT=$REPLY
  ORIN_CACHE_DIR=""
}

run_cmd() { # $1 position in SEGW of the command word, $2 end
  local p=$1 e=$2 k w base guard=0 real=0 x
  while ((p < e)); do
    ((guard++ > 30)) && deny "too many nested command wrappers; failing closed."
    k=${SEGW[p]}
    w=${TW[k]}
    if [[ $w =~ ^([A-Za-z_][A-Za-z0-9_]*)\+?= ]]; then
      set_assign "${BASH_REMATCH[1]}" "$k" 0
      p=$((p + 1))
      continue
    fi
    if ((TD[k])); then
      dynamic_code "a command name built from a variable or substitution"
      return 0
    fi
    base=${w##*/}
    [[ $base == *[A-Z]* ]] && base=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')
    case $base in
      '!' | '{' | '}' | then | do | else | elif | if | while | until | done | fi | esac | '(' | ')')
        p=$((p + 1))
        continue
        ;;
      for | case | select | in | function) return 0 ;;
      time)
        p=$((p + 1))
        [[ ${TW[${SEGW[p]}]} == -p ]] && p=$((p + 1))
        continue
        ;;
      env | genv)
        p=$((p + 1))
        while ((p < e)); do
          x=${TW[${SEGW[p]}]}
          case $x in
            -u | --unset) p=$((p + 2)) ;;
            -C | --chdir)
              local dk=${SEGW[p + 1]}
              if ((TD[dk])); then
                SEG_DIR=""
                VCWD_KNOWN=0
              else
                SEG_DIR=${TW[dk]}
                [[ $SEG_DIR == /* ]] || SEG_DIR="$VCWD/$SEG_DIR"
              fi
              p=$((p + 2))
              ;;
            -P)
              SEG_PATH=1
              p=$((p + 2))
              ;;
            -P*)
              SEG_PATH=1
              p=$((p + 1))
              ;;
            -S | --split-string | -S* | --split-string=*)
              local sk
              if [[ $x == -S || $x == --split-string ]]; then
                sk=${SEGW[p + 1]}
                p=$((p + 2))
              else
                sk=${SEGW[p]}
                p=$((p + 1))
              fi
              if ((TD[sk])); then
                dynamic_code "\`env -S\` with expanded text"
                return 0
              fi
              local str=${TW[sk]}
              str=${str#--split-string=}
              str=${str#-S}
              while ((p < e)); do
                str+=" $(printf '%q' "${TW[${SEGW[p]}]}")"
                ((TD[SEGW[p]])) && {
                  dynamic_code "\`env -S\` with expanded text"
                  return 0
                }
                p=$((p + 1))
              done
              QUEUE+=("$str")
              return 0
              ;;
            --) p=$((p + 1)); break ;;
            -*) p=$((p + 1)) ;;
            *) break ;;
          esac
        done
        continue
        ;;
      sudo | doas)
        p=$((p + 1))
        while ((p < e)); do
          x=${TW[${SEGW[p]}]}
          case $x in
            -u | -g | -p | -C | -D | -h | -r | -t | -U | -T) p=$((p + 2)) ;;
            --) p=$((p + 1)); break ;;
            -*) p=$((p + 1)) ;;
            *) break ;;
          esac
        done
        continue
        ;;
      command)
        p=$((p + 1))
        while ((p < e)); do
          x=${TW[${SEGW[p]}]}
          case $x in
            -v | -V) return 0 ;;
            -p) real=1; p=$((p + 1)) ;;
            -*) p=$((p + 1)) ;;
            *) break ;;
          esac
        done
        continue
        ;;
      builtin | exec | nohup | unbuffer | chronic | caffeinate | stdbuf | nice | setsid | arch | timeout | gtimeout | xargs | gxargs | npx | bunx | pnpx | watch | flock)
        p=$((p + 1))
        while ((p < e)); do
          x=${TW[${SEGW[p]}]}
          case "$base:$x" in
            exec:-a | nice:-n | caffeinate:-t | caffeinate:-w | arch:-arch | timeout:-s | timeout:-k | gtimeout:-s | gtimeout:-k | watch:-n | npx:-p | npx:--package | bunx:-p)
              p=$((p + 2))
              ;;
            xargs:-I | xargs:-J | xargs:-L | xargs:-n | xargs:-P | xargs:-R | xargs:-S | xargs:-s | xargs:-E | xargs:-d | xargs:-a | gxargs:-I | gxargs:-n | gxargs:-P | gxargs:-d)
              p=$((p + 2))
              ;;
            *:--) p=$((p + 1)); break ;;
            *:-*) p=$((p + 1)) ;;
            *) break ;;
          esac
        done
        if [[ $base == timeout || $base == gtimeout ]] && ((p < e)); then p=$((p + 1)); fi
        if [[ $base == flock ]] && ((p < e)); then p=$((p + 1)); fi
        if [[ $base == watch ]] && ((p < e)); then
          local wstr="" wi
          for ((wi = p; wi < e; wi++)); do wstr+=" ${TW[${SEGW[wi]}]}"; done
          QUEUE+=("$wstr")
          return 0
        fi
        continue
        ;;
      pnpm | npm | yarn)
        case ${TW[${SEGW[p + 1]}]} in
          exec | dlx | x)
            p=$((p + 2))
            while ((p < e)) && [[ ${TW[${SEGW[p]}]} == -* ]]; do p=$((p + 1)); done
            continue
            ;;
        esac
        return 0
        ;;
      sh | bash | zsh | dash | ksh | fish | csh | tcsh | mksh)
        analyze_shell "$p" "$e"
        return 0
        ;;
      eval)
        local estr="" ei
        for ((ei = p + 1; ei < e; ei++)); do
          if ((TD[SEGW[ei]])); then
            dynamic_code "\`eval\` of expanded text"
            return 0
          fi
          estr+=" ${TW[${SEGW[ei]}]}"
        done
        QUEUE+=("$estr")
        return 0
        ;;
      source | .)
        if ((p + 1 < e)) && ((TD[SEGW[p + 1]])); then dynamic_code "sourcing a file whose path is built at runtime"; fi
        if ((p + 1 >= e)) && ((PIPED_IN)); then dynamic_code "sourcing generated text"; fi
        return 0
        ;;
      gh)
        [[ $w == */* && $w != "$HOME/.local/bin/gh" ]] && real=1
        analyze_gh $((p + 1)) "$e" "$real"
        return 0
        ;;
      entire)
        analyze_entire $((p + 1)) "$e"
        return 0
        ;;
      curl | wget | http | https | xh | xhs | curlie)
        analyze_http $((p + 1)) "$e" "$base"
        return 0
        ;;
      cd | pushd)
        do_cd $((p + 1)) "$e"
        return 0
        ;;
      popd)
        VCWD_KNOWN=0
        return 0
        ;;
      export | declare | typeset | local | readonly)
        for ((x = p + 1; x < e; x++)); do
          k=${SEGW[x]}
          if [[ ${TW[k]} =~ ^([A-Za-z_][A-Za-z0-9_]*)\+?= ]]; then set_assign "${BASH_REMATCH[1]}" "$k" 1; fi
        done
        return 0
        ;;
      alias)
        for ((x = p + 1; x < e; x++)); do
          k=${SEGW[x]}
          if [[ ${TW[k]} =~ ^([^=]+)=(.*)$ ]]; then
            [[ ${BASH_REMATCH[1]} == gh || ${BASH_REMATCH[1]} == entire ]] && PATH_TAMPERED=1
            if ((TD[k])); then dynamic_code "an alias built from expanded text"; else QUEUE+=("${BASH_REMATCH[2]}"); fi
          fi
        done
        return 0
        ;;
      hash)
        for ((x = p + 1; x < e; x++)); do [[ ${TW[${SEGW[x]}]} == -p ]] && PATH_TAMPERED=1; done
        return 0
        ;;
      git)
        # git aliases that shell out: git config alias.x '!gh pr merge', git -c alias.x=!...
        for ((x = p + 1; x < e; x++)); do
          k=${SEGW[x]}
          case ${TW[k]} in
            alias.*=!* | *.alias.*=!*) QUEUE+=("${TW[k]#*=!}") ;;
            '!'*) [[ ${TW[${SEGW[x - 1]}]} == alias.* ]] && QUEUE+=("${TW[k]#!}") ;;
          esac
        done
        analyze_generic "$p" "$e" git
        return 0
        ;;
      *)
        analyze_generic "$p" "$e" "$base"
        return 0
        ;;
    esac
  done
  # Only assignments (e.g. `PATH=/x:$PATH` on its own): they persist for the rest of the command.
  if ((SEG_PATH)); then PATH_TAMPERED=1; fi
  if [[ -n $SEG_REPO ]] || ((SEG_REPO_DYN)); then
    GLOBAL_REPO=$SEG_REPO
    GLOBAL_REPO_DYN=$SEG_REPO_DYN
  fi
  ((SEG_GITDIR)) && GLOBAL_GITDIR=1
  return 0
}

analyze_segment() { # token range [$1, $2)
  local a=$1 b=$2 k op
  SEGW=()
  SEGH=()
  SEG_STDIN=0
  SEG_PATH=0
  SEG_REPO=""
  SEG_REPO_DYN=0
  SEG_GITDIR=0
  SEG_DIR=""
  PIPED_IN=0
  if ((a > 0)) && [[ ${TK[a - 1]} == s && (${TW[a - 1]} == '|' || ${TW[a - 1]} == '|&') ]]; then PIPED_IN=1; fi
  k=$a
  while ((k < b)); do
    case ${TK[k]} in
      w) SEGW+=("$k") ;;
      h) SEGH+=("$k") ;;
      r)
        op=${TW[k]}
        if ((k + 1 < b)) && [[ ${TK[k + 1]} == w || ${TK[k + 1]} == h ]]; then
          if [[ $op == '<<<' || ${TK[k + 1]} == h ]]; then
            SEGH+=($((k + 1)))
          else
            case $op in
              '>' | '>>' | '>|' | '&>' | '&>>' | '<>')
                norm_pat "${TP[k + 1]}"
                tamper_hit && deny "agents may not overwrite the gh shim or the agent hook settings (${TW[k + 1]})."
                ;;
              '<') SEG_STDIN=1 ;;
            esac
          fi
          k=$((k + 1))
        fi
        ;;
    esac
    k=$((k + 1))
  done
  ((${#SEGW[@]})) || return 0
  run_cmd 0 ${#SEGW[@]}
}

analyze_cmd() {
  local str=$1 t start
  check_names "$str"
  tokenize "$str" || deny "could not parse the command (${PARSE_ERR:-syntax}); failing closed."
  for ((t = 0; t < ${#TW[@]}; t++)); do
    case ${TK[t]} in w | h) check_names "${TW[t]}" ;; esac
  done
  start=0
  for ((t = 0; t <= ${#TW[@]}; t++)); do
    if ((t == ${#TW[@]})) || [[ ${TK[t]} == s ]]; then
      if ((t > start)); then
        check_paths "$start" "$t"
        analyze_segment "$start" "$t"
      fi
      start=$((t + 1))
    fi
  done
}

check_paths() { # token range [$1, $2); runs after earlier segments' cd took effect
  local t
  for ((t = $1; t < $2; t++)); do
    case ${TK[t]} in
      w)
        local lit=${TW[t]//$'\x01'/}
        if ((TD[t])); then
          [[ $lit == */* && ${#lit} -ge 4 ]] || continue
          # A word that starts with a variable may be absolute: let it start anywhere.
          if [[ ${TP[t]} == '*'* ]]; then
            check_path_pat "/**/${TP[t]}"
            continue
          fi
        fi
        check_path_pat "${TP[t]}"
        [[ ${TW[t]} == *=* ]] && check_path_pat "${TP[t]#*=}"
        ;;
    esac
  done
  return 0
}

analyze_patch() { # apply_patch payloads: check the file headers
  local line f
  while IFS= read -r line; do
    case $line in
      '*** Add File: '* | '*** Update File: '* | '*** Delete File: '* | '*** Move to: '*)
        f=${line#*: }
        check_names "$f"
        [[ $f == '~/'* ]] && f="$HOME/${f#\~/}"
        pesc "$f"
        norm_pat "$REPLY"
        prot_hit && deny "this patch touches the orin-dx-pr-bot directories ($f)."
        tamper_hit && deny "agents may not modify the gh shim or the agent hook settings ($f)."
        ;;
    esac
  done <<<"$1"
}

# ---------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------
command -v jq >/dev/null 2>&1 || deny "jq is not installed; failing closed."
INPUT=$(cat) || deny "could not read the hook payload; failing closed."
[[ -n $INPUT ]] || deny "empty hook payload; failing closed."
((${#INPUT} <= 1000000)) || deny "hook payload too large; failing closed."
printf '%s' "$INPUT" | jq -e 'type == "object"' >/dev/null 2>&1 || deny "the hook payload is not a JSON object; failing closed."

JQ_MAIN='
def cmdv: (.tool_input.command // .tool_input.cmd // .toolCall.args.CommandLine // .toolCall.args.command // .tool_input.args.command // null);
(if ([.. | strings | select(contains("\u0000"))] | length) > 0 then "nul" else "ok" end), "\u0000",
((.tool_name // .toolCall.name // "") | tostring), "\u0000",
(if cmdv == null then "0" else "1" end), "\u0000",
((.toolCall.args.Cwd // .tool_input.workdir // .tool_input.cwd // .cwd // "") | tostring), "\u0000",
(cmdv | if . == null then "" elif type == "array" then map(tostring | @sh) | join(" ") else tostring end), "\u0000"'

{
  IFS= read -r -d '' P_NUL
  IFS= read -r -d '' TOOL
  IFS= read -r -d '' HAS_CMD
  IFS= read -r -d '' CWD
  IFS= read -r -d '' CMD
} < <(printf '%s' "$INPUT" | jq -j "$JQ_MAIN" 2>/dev/null)

[[ $P_NUL == ok ]] || deny "the hook payload contains NUL bytes or could not be decoded; failing closed."
[[ $HAS_CMD == 0 || $HAS_CMD == 1 ]] || deny "could not decode the hook payload; failing closed."

VCWD=${CWD:-$PWD}
[[ $VCWD == '~'* ]] && VCWD="$HOME${VCWD#\~}"
[[ $VCWD == /* ]] || VCWD="$PWD/$VCWD"
VCWD_KNOWN=1
pesc "$VCWD"
VCWD_PAT=$REPLY
norm_pat "$VCWD_PAT"
prot_hit && deny "agents may not work inside the orin-dx-pr-bot key/token directories."

PATH_TAMPERED=0
GLOBAL_REPO=""
GLOBAL_REPO_DYN=0
GLOBAL_GITDIR=0
QUEUE=()

if [[ $HAS_CMD == 1 ]]; then
  ((${#CMD} <= 200000)) || deny "command too long to check; failing closed."
  if [[ $CMD == *'*** Begin Patch'* ]]; then
    analyze_patch "$CMD"
    allow
  fi
  CMD_SENSITIVE=0
  imatch "$CMD" "$SENS_RE" && CMD_SENSITIVE=1
  QUEUE=("$CMD")
  QI=0
  while ((QI < ${#QUEUE[@]})); do
    ((QI > 64)) && deny "too many nested commands; failing closed."
    analyze_cmd "${QUEUE[QI]}"
    QI=$((QI + 1))
  done
  allow
fi

# File tools (Read/Edit/Write/Grep/Glob/LS, Codex apply_patch, Antigravity view_file/list_dir/...):
# check every path-like argument. Content arguments (new_string, content, Grep's regex) are not paths.
case $TOOL in
  Grep | grep_search | search_file_content | codebase_search) SKIP_KEYS='^(pattern|query|Query|SearchQuery|regex)$' ;;
  *) SKIP_KEYS='^$' ;;
esac
SEARCH_TOOL=0
case $TOOL in Grep | Glob | LS | list_dir | grep_search | find_by_name | search_files | list_directory | glob | search_file_content | codebase_search) SEARCH_TOOL=1 ;; esac
WRITE_TOOL=0
case $TOOL in Write | Edit | MultiEdit | NotebookEdit | write_to_file | replace_file_content | multi_replace_file_content | apply_patch | write_file | replace | edit_file | create_file) WRITE_TOOL=1 ;; esac

JQ_PATHS='
(.tool_input // .toolCall.args // {}) as $a
| [ $a | paths(type == "string") as $p
    | select(($p | map(tostring) | join(".")) | test("(path|file|dir|glob|pattern|target|uri|url|cwd|include|exclude|location|notebook|folder)"; "i"))
    | select(($p[-1] | tostring) | test($skip) | not)
    | $a | getpath($p) ]
| .[] | (., "\u0000")'
PATH_ARGS=0
while IFS= read -r -d '' S; do
  PATH_ARGS=$((PATH_ARGS + 1))
  check_names "$S"
  [[ $S == *$'\n'* || ${#S} -gt 4096 ]] && continue
  [[ $S == file://* ]] && S=${S#file://}
  [[ $S == '~' || $S == '~/'* ]] && S="$HOME${S#\~}"
  # Literal path, but keep glob characters live (Glob/find_by_name patterns).
  P=${S//\\/\\\\}
  P=${P//\{/\\\{}
  P=${P//\}/\\\}}
  norm_pat "$P"
  prot_hit && deny "agents may not read, list or edit the orin-dx-pr-bot key/token/helper directories ($S)."
  ((WRITE_TOOL)) && tamper_hit && deny "agents may not modify the gh shim or the agent hook settings ($S)."
  ((SEARCH_TOOL)) && anc_hit && deny "searching $S would walk into the orin-dx-pr-bot key/token directories. Search a narrower directory."
done < <(printf '%s' "$INPUT" | jq -j --arg skip "$SKIP_KEYS" "$JQ_PATHS" 2>/dev/null)

if ((SEARCH_TOOL)); then
  HAS_DIR=$(printf '%s' "$INPUT" | jq -r '(.tool_input // .toolCall.args // {}) | (has("path") or has("SearchPath") or has("DirectoryPath") or has("SearchDirectory") or has("dir_path"))' 2>/dev/null) \
    || deny "could not decode the hook payload; failing closed."
  if [[ $HAS_DIR != true ]]; then
    norm_pat "$VCWD_PAT"
    anc_hit && deny "searching from $VCWD would walk into the orin-dx-pr-bot key/token directories. Search a narrower directory."
  fi
fi

# Patches carried as plain strings (Codex apply_patch input).
PATCH=$(printf '%s' "$INPUT" | jq -r '[(.tool_input // .toolCall.args // {}) | .. | strings | select(contains("*** Begin Patch"))] | join("\n")' 2>/dev/null) \
  || deny "could not decode the hook payload; failing closed."
[[ -n $PATCH ]] && analyze_patch "$PATCH"
allow
