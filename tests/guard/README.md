# orin-dx PR-bot guard: design note

`bin/pr-bot-guard.sh` is a PreToolUse hook. It reads one hook payload and denies tool calls that would
use the bot's credentials, act on orin-dx PRs as the human, or route around the `gh` shim.
`bin/gh-shim` is the `gh` wrapper that opens orin-dx PRs as `orin-dx-pr-bot`.

**The guard is advisory.** It sees only the text of a tool call. It cannot see what a script file,
a runtime-built string, or an interpreter (python, node, make, npm scripts, git hooks) will do. The
real boundaries are:

1. the OS sandbox read-deny on `~/.config/orin-dx`, `~/.cache/orin-dx`,
   `~/Library/{Application Support,Caches}/OrinDX-PR-Bot`;
2. agent settings an agent cannot rewrite (root-owned or managed settings), so the hook cannot be
   removed;
3. GitHub rulesets and required reviews, so a PR an agent opens or edits as the human still needs a
   human approval that is not the author's.

Run the tests with `bash tests/guard/run.sh` (no network; `VERBOSE=1` prints each deny reason).
Last run: 193 passed, 0 failed (the guard, the Antigravity adapter, and the shim's parsing and
`pr create` decisions).

## How the guard reads a command

A conservative shell lexer handles single and double quotes, `\` escapes, `$'..'` (decoded), `~`,
`$HOME` and `${HOME}`, brace and glob patterns, heredocs and here-strings, `$(..)`, backticks and
`<(..)`. Command and process substitutions, `bash|sh|zsh -c` strings, `eval` arguments, `env -S`,
`watch`, alias values, git `!` aliases and shell heredocs are re-analysed as commands. Wrappers
(`env`, `sudo`, `command`, `exec`, `nohup`, `time`, `timeout`, `xargs`, `npx`, `pnpm exec`,
`find -exec`, and others) are unwrapped. `cd` is tracked for later relative paths. Any parse failure
denies.

## Rules

| Rule | Stops | Cannot stop |
|---|---|---|
| R1 protected names and paths | Any mention of the key, store, caches, helper or mint, including quote tricks (`.conf''ig`), `$HOME`/`~`, `../` normalisation, globs (`~/.c*/orin*/*`), braces, `cd` and a relative path, `bash|sh|python|node <file>` inside those dirs, a squeezed form (`"/.config/" + "orin-dx"` in python), and `age -d`. File tools are covered through their path arguments. | Paths built at runtime from pieces with no literal hint (`$A$B`), symlinks made earlier, a script that reads the files. The sandbox read-deny is the boundary here. |
| R2 recursive tools | `grep -r`, `rg`, `find`, `fd`, `tar`, `zip`, `cp -r`, `rsync` and the Grep/Glob/LS tools pointed at `~`, `~/.config`, `~/Library`, `/` and other ancestors of a protected dir. | Recursive work done inside a script or interpreter. |
| R3 real gh | `/opt/homebrew/bin/gh`, Cellar paths, `/usr/local/bin/gh`, `command -p gh`, `PATH=…`/`export PATH`/`env -i PATH=`/`env -P`, `hash -p`, `alias gh=`, copying or linking the gh binary, and a renamed copy (`./g pr create`). PR writes and PR-endpoint API writes through it are denied everywhere. | A real gh started by a script, or a copy made by an earlier session. |
| R4 gh pr writes | `gh pr merge|review|ready|edit|close|reopen|update-branch|lock|unlock|revert` when the target is orin-dx (current checkout's remotes, `-R`/`--repo` in all forms, URLs, `GH_REPO`). Also `pr create --web`, gh aliases and extensions in orin-dx, `gh alias set|import`, and runtime-built gh subcommands. Reads (`view`, `list`, `checks`, `diff`, `status`, `run view`) and `pr create` through the shim stay allowed. | Writes from a script; an alias defined by the human before the session. |
| R5 gh api | REST writes (`-X` not GET, or `-f/-F/--input`) to `pulls`, `merge(s)`, `reviews`, `requested_reviewers` or `auto-merge` on orin-dx (or `{owner}` in an orin-dx checkout, `repositories/<id>`, runtime-built endpoints). Also GraphQL mutations on pull requests, reviews or merges anywhere, since node ids hide the repo, and GraphQL writes whose query it cannot read (`--input`, `@file`). | Mutations whose text avoids those words. Every PR mutation name contains them, but a query loaded at runtime from a variable is only caught by the "cannot read" rule. |
| R6 curl / wget / httpie | Writes to `api.github.com` PR, review or merge endpoints of orin-dx, `repositories/<id>`, PR GraphQL bodies, and `-K` config files in GitHub or orin-dx context. Writes to a URL built at runtime are denied in orin-dx repos. | HTTP from python, node or other clients, and a token pulled from `gh auth token` into a script. |
| R7 Entire | `entire trail link|create|merge|approve` (including `bash -c`, `npx`, absolute path, dynamic verb) in an orin-dx checkout unless the current branch already has an open PR authored by `orin-dx-pr-bot`. The check is one read-only call: `gh pr list -R orin-dx/<repo> --head <branch> --state open --json author` with the human's login. Any error, timeout or unknown branch denies. | Entire opening or editing PRs from anything other than those subcommands, such as git hooks it installs or a background daemon. The real fix is to remove Entire's saved GitHub login (castrog), or give it a bot token. Note that `trail merge|approve` is still allowed when a bot PR exists. If those act on the PR as the human, require a human for them too. |
| R8 hidden code | Dynamic command names, `eval`/`bash -c` of expanded text, `… | sh`, `bash -s`, heredocs with expansions fed to a shell, and sourcing a runtime path. These are denied in orin-dx checkouts or when the command mentions gh, entire, GraphQL or the API. | The same patterns elsewhere, and any script file the agent wrote earlier and then runs. |
| R9 tamper | Writes (redirections, `cp`, `mv`, `rm`, `sed -i`, `tee`, editors, the Write and Edit tools, `apply_patch`) to `~/.local/bin/gh`, `~/.claude/settings*.json`, `~/.codex/hooks.json`, `~/.codex/config.toml` and `~/.gemini/`. | A script doing it. Root-owned or managed settings are the boundary. |
| R10 fail closed | Invalid or empty JSON, NUL bytes, unterminated quotes or substitutions, more than 64 nested commands, a missing `jq`, an unset HOME, and any internal error (an EXIT trap denies). | n/a |

**Latency.** About 50–70 ms per tool call (bash and jq). The Entire check adds one GitHub API round
trip, usually 0.5–2 s, only for gated `entire trail` commands in orin-dx checkouts. It times out
after 10 s and then denies.

**Known false positives (deliberate fail-closed).**

- `export PATH=…; gh pr create` is denied.
- A path whose prefix is a variable and that contains a component named `orin-dx`
  (`cd $SRC/orin-dx/x`) is denied.
- `gh pr merge $N` is denied even outside orin-dx, because the argument could be an orin-dx URL.
- Heredoc bodies fed to a command are scanned for the protected names.
- Inside an orin-dx checkout, the shim refuses `pr create -R <other-owner>/…`.

## gh shim

- It runs under `#!/bin/bash` with a pinned PATH. The real gh is `/opt/homebrew/bin/gh` or
  `/usr/local/bin/gh`, and must be a binary, not a script.
- It has no environment overrides. The home directory comes from `dscl`, not `$HOME`. The mint is
  `<home>/.config/orin-dx/pr-bot-token` and must be owned by you and not group- or world-writable.
  It runs under `env -i`, so `GH_REAL`, `PR_BOT_*` and `PATH` cannot reach it (this is tested).
- It handles `pr create` and `pr new`. `-R`/`--repo` is read in every spelling: `-R x`, `-Rx`,
  `-R=x`, `--repo x`, `--repo=x`. Values can be `OWNER/REPO`, `HOST/OWNER/REPO`, URLs, or
  `git@HOST:OWNER/REPO`. Combined short flags such as `-dw` are understood.
- If the command, `GH_REPO`, or any remote of the checkout mentions orin-dx, the shim either opens
  the PR as the bot (github.com, orin-dx owner, valid name, minted `ghs_` token) or refuses. It never
  falls back to the human's credentials.
- `--web` is refused. `--help` runs gh with an empty config dir and no tokens.
- Non-built-in first words (aliases and extensions) are refused inside orin-dx checkouts.
- The bot token reaches gh only through `GH_TOKEN`, never through argv. `GH_HOST`, the enterprise
  tokens and `GH_DEBUG` are dropped, and `GH_CONFIG_DIR` is pinned.

## Adapters: which hook keys are confirmed

- **Claude Code (confirmed in Claude Code's hook docs).** PreToolUse; a regex `matcher` on tool
  names; stdin `tool_name`/`tool_input`/`cwd`; exit 2 blocks and shows stderr;
  `hookSpecificOutput.permissionDecision: "deny"`. Across several hooks, a deny wins over the rtk
  hook's allow. See `adapters/claude-settings.example.json`: it extends the matcher to the file tools.
- **Codex (`adapters/codex-hooks.example.json`).** The `hooks.PreToolUse[].matcher/hooks[].type/command`
  layout is copied from the existing file. Unverified: `onFailure: "block"`, the `"*"` matcher, the
  tool names (`apply_patch` and others), Claude-compatible payload fields, and whether a deny beats
  the rtk entry's forced allow. Codex reads files mostly through shell commands, which the Bash
  rules cover. The guard also accepts `command` as an argv array and `apply_patch` bodies.
- **Antigravity (`adapters/antigravity-guard.sh`).** Unverified: the `toolCall.name/args` payload
  (`CommandLine`, `Cwd`, `AbsolutePath`, `TargetFile`, `DirectoryPath`, `SearchPath`), the
  `{"decision":"deny","reason":…}` output, and the hook registration keys. The adapter fails closed
  when the guard is missing, HOME is unset, the payload is empty, or the guard crashes or returns any
  unexpected output. It resolves the guard through `$HOME`, falling back to `dscl`. Register it for
  all tools with an absolute path, not `~`.

## Residual gaps outside this directory

- `bin/pr-bot-token` still passes the App JWT in argv (`gh api -H "Authorization: Bearer …"`) and
  still honours `GH_REAL`, `PR_BOT_HELPER` and `PR_BOT_CACHE`. The shim scrubs those via `env -i`,
  but the script itself should drop them. It should send the header with
  `curl -H @<0600 file>` or over stdin.
- `GH_TOKEN` in the environment can be read by other processes running as the same user, as argv can.
  The token is repo-scoped and lasts one hour.
