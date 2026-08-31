#!/usr/bin/env bash
#
# Reject AI-assistant attribution in commit metadata.
#
# The rule this enforces is narrow and worth stating precisely, because the obvious
# implementation gets it wrong: it inspects **Git metadata only** - author identity,
# committer identity, and the trailer block of the commit message. It never looks at
# file content.
#
# That distinction is the whole design. A NOTICE file naming "Anthropic, PBC" as the
# copyright holder of an MIT-licensed dependency is a legal requirement, not a claim that
# an assistant contributed to this repository. A guard that grepped the working tree would
# fail on exactly the file that licence compliance requires, and the usual response to a
# guard that cries wolf is to delete the guard. So:
#
#   checked      author name/email, committer name/email, and Co-authored-by /
#                Signed-off-by / Assisted-by / Generated-by / Created-by trailer VALUES
#   not checked  source files, documentation, dependency manifests, NOTICE, licences
#
# Human co-authors pass. Upstream attribution passes. Documentation discussing an AI
# vendor passes. What fails is an assistant being recorded as having authored the work.
#
# Usage:
#   tools/check-authorship.sh                 # commits not yet on the upstream branch
#   tools/check-authorship.sh <range>         # an explicit range, e.g. HEAD~20..HEAD
#   tools/check-authorship.sh --all           # every commit on every ref
#
# Install as a pre-push hook:
#   ln -s ../../tools/check-authorship.sh .git/hooks/pre-push
#
set -euo pipefail

# Identities that must never appear as an author, committer or co-author of this work.
# Matched case-insensitively against the identity string, not against file content.
FORBIDDEN='claude|anthropic|copilot|chatgpt|openai|gpt-[0-9]|\bai[ -]assistant\b|\bbot\b'

# Trailers that assert authorship or contribution.
TRAILERS='co-authored-by|signed-off-by|assisted-by|generated-by|created-by|authored-with|contributor'

range="${1:-}"
if [ "$range" = "--all" ]; then
  revs="--all"
elif [ -n "$range" ]; then
  revs="$range"
else
  # Default: whatever this branch adds on top of its upstream. Falls back to the whole
  # history on a branch with no upstream, which is the right answer for a first push.
  if upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null); then
    revs="${upstream}..HEAD"
  else
    revs="HEAD"
  fi
fi

fail=0

# --- identities -------------------------------------------------------------------
# One record per commit so a match can be reported against the commit that carries it.
while IFS='|' read -r sha an ae cn ce; do
  [ -z "${sha:-}" ] && continue
  for field in "$an" "$ae" "$cn" "$ce"; do
    if printf '%s' "$field" | grep -qiE "$FORBIDDEN"; then
      echo "FAIL ${sha:0:9} AI identity in commit metadata: '${field}'"
      echo "     author=${an} <${ae}>  committer=${cn} <${ce}>"
      fail=1
    fi
  done
done < <(git log --format='%H|%an|%ae|%cn|%ce' $revs 2>/dev/null)

# --- trailers ---------------------------------------------------------------------
# Only the value side of a trailer is tested. "Co-authored-by: Jane <jane@example.com>"
# is fine; the same trailer naming an assistant is not.
while read -r sha; do
  [ -z "${sha:-}" ] && continue
  while IFS= read -r line; do
    value="${line#*:}"
    if printf '%s' "$value" | grep -qiE "$FORBIDDEN"; then
      echo "FAIL ${sha:0:9} AI attribution trailer: ${line}"
      fail=1
    fi
  done < <(git log -1 --format='%B' "$sha" | grep -iE "^[[:space:]]*(${TRAILERS}):" || true)
done < <(git log --format='%H' $revs 2>/dev/null)

if [ "$fail" -ne 0 ]; then
  cat <<'MSG'

Commit metadata records an AI assistant as an author, committer or co-author.

Fix the identity rather than the wording:
  git commit --amend --reset-author            # for the most recent commit
  git rebase -i <base> --exec 'git commit --amend --reset-author --no-edit'

This check reads Git metadata only. It does not read file content, so upstream
copyright notices and documentation that discusses an AI vendor are unaffected.
MSG
  exit 1
fi

count=$(git rev-list --count $revs 2>/dev/null || echo 0)
echo "authorship clean: ${count} commit(s) checked in ${revs}"
