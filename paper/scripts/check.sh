#!/bin/sh
# Pre-submission checks. Run from the paper directory: sh scripts/check.sh
# Settings come from paper.conf (PAGE_LIMIT=...).
cd "$(dirname "$0")/.." || exit 1
PAGE_LIMIT=10
[ -f paper.conf ] && . ./paper.conf
fail=0
say() { printf '%-28s %s\n' "$1" "$2"; }

# 1. LaTeX errors, undefined references and citations
if [ -f main.log ]; then n=$(grep -cE '^!|(Reference|Citation).*undefined|There were undefined' main.log); else n="no log (run make)"; fi
say "LaTeX errors/undefined:" "$n"; [ "$n" = 0 ] || fail=1
grep -nE '^!|(Reference|Citation).*undefined|There were undefined' main.log 2>/dev/null | head -10

# 2. open items
t=$(grep -vhE '^[[:space:]]*%' sections/*.tex main.tex | grep -o '\\todo{' | wc -l | tr -d ' ')
m=$(grep -vhE '^[[:space:]]*%' sections/*.tex | grep -o '\\num{' | wc -l | tr -d ' ')
say "\\todo left:" "$t"; say "\\num (unmeasured) left:" "$m"
[ "$t" = 0 ] && [ "$m" = 0 ] || fail=1

# 3. banned words (STYLE.md 1.2); comments are skipped
BANNED='novel|powerful|seamless(ly)?|leverag(e|es|ed|ing)|utiliz(e|es|ed|ing|ation)|robust(ly|ness)?|cutting-edge|state-of-the-art|paradigm|holistic|synerg(y|ies)|comprehensive|groundbreaking|revolutionar(y|ize)|unprecedented|significantly|delve|crucial|pivotal|plethora|myriad|empower|unlock|facilitat(e|es|ed)'
b=$( { grep -vhE '^\s*%' sections/*.tex | grep -oiwE "$BANNED"; grep -vhE '^\s*%' sections/*.tex | grep -oiE 'harness(es|ed|ing)? (the|its|their)'; } | sort | uniq -c | sort -rn)
if [ -n "$b" ]; then say "banned words:" ""; echo "$b"; fail=1
  grep -nwiE "$BANNED" sections/*.tex | grep -vE ':\s*%' | head -15
else say "banned words:" 0; fi

# 4. e.g./i.e. in running text (allowed but flagged)
e=$(grep -vhE '^\s*%' sections/*.tex | grep -oE '\b(e\.g\.|i\.e\.)' | wc -l | tr -d ' ')
say "e.g./i.e. (prefer words):" "$e"

# 5. long sentences (> 35 words), rough
python3 - <<'PY' 2>/dev/null
import re,glob
long=0
for f in sorted(glob.glob('sections/*.tex')):
    txt=''.join(l if not l.lstrip().startswith('%') else '\n' for l in open(f))
    txt=re.sub(r'\\begin\{(lstlisting|tikzpicture|tabular)\}.*?\\end\{\1\}',' ',txt,flags=re.S)
    txt=re.sub(r'\n\s*\n|\\item|\\(sub)*section\*?\{[^}]*\}|\\paragraph\{[^}]*\}|\\(begin|end)\{[^}]*\}',' . ',txt)
    txt=re.sub(r'\\[a-zA-Z]+\*?(\[[^]]*\])?',' ',txt)
    for s in re.split(r'(?<=[.?!:;])\s+',txt):
        w=len(s.split())
        if w>35: long+=1; print(f'  {f}: {w} words: {" ".join(s.split()[:10])} ...')
print(f'{"sentences > 35 words:":<28} {long}')
PY

# 6. page limit: page where References starts
if [ -f main.pdf ]; then
  pages=$(pdfinfo main.pdf 2>/dev/null | awk '/^Pages/{print $2}')
  ref=""
  i=1; while [ "$i" -le "${pages:-0}" ]; do
    if pdftotext -f $i -l $i main.pdf - 2>/dev/null | grep -qiE '^references$'; then ref=$i; break; fi
    i=$((i+1)); done
  say "pages / refs start on:" "${pages:-?} / ${ref:-?} (limit $PAGE_LIMIT)"
  [ -n "$ref" ] && [ "$ref" -gt $((PAGE_LIMIT+1)) ] && fail=1
  [ -n "$ref" ] && [ "$ref" -eq $((PAGE_LIMIT+1)) ] && echo "  check by eye: main text must end on page $PAGE_LIMIT"
fi

# 7. anonymity
a=$(grep -nE '/Users/|/home/|github\.com/[A-Za-z]' sections/*.tex main.tex | grep -vE '^[^:]+:[0-9]+:[[:space:]]*%' | grep -v anonymous)
[ -n "$a" ] && { say "identifying paths/URLs:" ""; echo "$a"; fail=1; } || say "identifying paths/URLs:" 0

[ $fail = 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $fail
