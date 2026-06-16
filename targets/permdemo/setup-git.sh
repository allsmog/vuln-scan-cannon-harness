#!/bin/sh
# Recreate the demo git history the commit-archaeology generator reads:
# a past "Fix SQL injection in /search" commit + app.py as a churn hotspot.
# Run once from anywhere; it operates on this target's src/.
set -e
cd "$(dirname "$0")/src"
if [ -d .git ]; then
  echo "permdemo git history already present — nothing to do."
  exit 0
fi
git init -q .
git config user.email demo@cannon.local
git config user.name "cannon demo"
git config commit.gpgsign false
git add db.py requirements.txt && git commit -q -m "Initial DB helper and deps"
git add app.py && git commit -q -m "Add search and profile endpoints"
printf '\n# rev: parameterize search query\n' >> app.py && git add app.py && git commit -q -m "Fix SQL injection in /search endpoint"
printf '\n# rev: tidy helper\n' >> db.py && git add db.py && git commit -q -m "Refactor db helper for clarity"
printf '\n# rev: add config route\n' >> app.py && git add app.py && git commit -q -m "Add YAML config loader endpoint"
echo "permdemo git history created:"
git log --oneline
echo
echo "Now try:  cannon permute permdemo --sources commits,threat-intel --budget 5.00"
