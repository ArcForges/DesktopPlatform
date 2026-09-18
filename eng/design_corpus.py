# SPDX-License-Identifier: AGPL-3.0-only
"""Document-scoped Markdown integrity checks; no historical programs are executed."""

import collections
import html
import posixpath
import re
import subprocess
from urllib.parse import unquote, urlsplit

ID = re.compile(r'(?<![\w-])(?:WP-\d{2}(?:\.\d{2})?|P2-\d{3}|F-[A-Z]{2}-[1-9]\d*|[A-Z][A-Z0-9]{0,5}-(?:[A-Z]\d{1,3}|\d{2,3}[a-z]?))(?![\w-]|\.\d)')
LINK = re.compile(r'\[([^\]\n]+)\]\(([^)\n]+)\)')
ANCHOR = re.compile(r'<a\s+id="([^"]+)"\s*>\s*</a>')
STANDARD = {'SHA-256', 'SHA-512', 'UTF-16', 'UTF-32', 'IEEE-754', 'P-256'}

def visible(s):
    return re.sub(r'[`*~]', '', html.unescape(LINK.sub(lambda m: m[1], re.sub(r'<[^>]*>', '', s))))

def cells(line):
    return [c.strip() for c in re.split(r'(?<!\\)\|', line.strip())[1:-1]]

def lines(text):
    fence = None
    for n, line in enumerate(text.splitlines(), 1):
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})(.*)$', line)
        if match:
            if fence is None:
                fence = match[1]
            elif match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2].strip():
                fence = None
            continue
        if fence is None:
            yield n, line
    if fence:
        raise ValueError('unclosed code fence')

def heading_slug(text):
    return re.sub(r'[^\w\- ]', '', visible(text).lower()).replace(' ', '-')

def anchor_identifier(anchor):
    if not anchor.startswith('rule-'):
        return None
    candidate = anchor[5:].upper()
    if ID.fullmatch(candidate):
        return candidate
    candidate = candidate[:-1] + candidate[-1:].lower()
    return candidate if ID.fullmatch(candidate) else None

def definition(line):
    if line.startswith('|'):
        cs = cells(line)
        if not cs or LINK.search(cs[0]):
            return None
        value = visible(cs[0]).strip()
    else:
        m = re.match(r'^#{1,6} (.+)$|^- (.+)$|^(\*\*[A-Z].+)$', line)
        if not m:
            return None
        value = visible(m[1] or m[2] or m[3]).strip()
        if LINK.match((m[1] or m[2] or m[3]).lstrip('*')): return None
    m = ID.match(value)
    if m and (len(value) == len(m[0]) or re.match(r'\s*[—:·]', value[len(m[0]):])):
        return m[0]
    return None

def load(root):
    entries = subprocess.check_output(['git', 'ls-files', '--stage', '-z'], cwd=root).decode().split('\0')
    paths = []
    for entry in filter(None, entries):
        metadata, path = entry.split('\t', 1)
        mode, _, stage = metadata.split()
        if mode not in {'100644', '100755'} or stage != '0':
            raise ValueError(f'unsupported Git source entry: {path}')
        paths.append(path)
    paths += subprocess.check_output(['git','ls-files','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
    paths = sorted(set(p for p in paths if p.endswith('.md') and not (p.startswith('docs/deprecated-inputs/') and p != 'docs/deprecated-inputs/README.md')))
    return {p: read_document(root, p) for p in paths}

def read_document(root, path):
    candidate = root / path
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'source escapes Design root: {path}')
    for current in [candidate, *candidate.parents]:
        if current == root:
            break
        if current.is_symlink() or (hasattr(current, 'is_junction') and current.is_junction()):
            raise ValueError(f'linked source is unsupported: {path}')
    return candidate.read_text(encoding='utf-8')

def collect(root, docs=None):
    docs = load(root) if docs is None else docs
    anchors = {}; defs = {}; errors = []
    for p, text in docs.items():
        parsed = list(lines(text)); existing = {}; counts = collections.Counter(); found = {}
        for n, line in parsed:
            for a in ANCHOR.findall(line):
                if a in existing: errors.append([p,n,'duplicate anchor',a])
                existing[a] = n
            h = re.match(r'^#{1,6} (.*)$', line)
            if h:
                base = heading_slug(h[1]); count = counts[base]; counts[base] += 1
                slug = base + (f'-{count}' if count else '')
                if slug in existing: errors.append([p,n,'duplicate anchor',slug])
                existing[slug] = n
            key = definition(line)
            if key:
                if key in found: errors.append([p,n,'duplicate definition',key])
                found[key] = n
        for a, n in existing.items():
            key = anchor_identifier(a)
            if key: found.setdefault(key,n)
        authored = {definition(line) for _, line in parsed}
        defs[p] = {k: {'line':n, 'anchor':'rule-'+k.lower(), 'stable':'rule-'+k.lower() in existing,
                       'kind':'definition' if k in authored else 'preserved-anchor'} for k,n in found.items()}
        anchors[p] = existing
    return docs, anchors, defs, errors

def audit(root, docs=None):
    docs, anchors, defs, errors = collect(root, docs)
    citations=[]; local_links=[]; raw=[]; missing=[]
    homes=collections.defaultdict(list)
    for p, dd in defs.items():
        for key, d in dd.items():
            homes[key].append(p)
            if not d['stable']: missing.append([p,d['line'],key])
    for p, text in docs.items():
        for n, line in lines(text):
            prose = re.sub(r'`+[^`]*`+', '', line)
            if re.search(r'\[[^\]]+\]\[[^\]]*\]|^\s*\[[^\]]+\]:', prose):
                errors.append([p,n,'unsupported reference-link syntax'])
            for match in LINK.finditer(line):
                uri=match[2].strip('<>')
                label_ids = [key for key in ID.findall(visible(match[1])) if key not in STANDARD]
                if urlsplit(uri).scheme or uri.startswith('//'):
                    if label_ids: errors.append([p,n,'external rule home',uri,label_ids])
                    continue
                name, _, fragment=uri.partition('#')
                target=posixpath.normpath(posixpath.join(posixpath.dirname(p),unquote(name))) if name else p
                local_links.append(dict(document=p, line=n, label=match[1], target=target, anchor=unquote(fragment)))
                if target.startswith('/') or target == '..' or target.startswith('../'):
                    errors.append([p,n,'link escapes Design root',uri])
                    continue
                if not (root/target).exists(): errors.append([p,n,'missing target',uri])
                elif fragment and unquote(fragment) not in anchors.get(target,{}): errors.append([p,n,'missing fragment',uri])
                for label in label_ids:
                    if fragment!='rule-'+label.lower():errors.append([p,n,'wrong rule anchor',uri,label])
                    if label not in defs.get(target,{}):errors.append([p,n,'missing rule definition',uri,label])
                    citations.append([p,n,label,target,fragment])
            spans=[m.span() for m in LINK.finditer(line)]+[m.span() for m in ANCHOR.finditer(line)]
            defid=definition(line)
            firstdef=True
            for m in ID.finditer(line):
                key=m[0]
                if any(a<=m.start()<b for a,b in spans) or key in STANDARD:continue
                if key==defid and firstdef:firstdef=False;continue
                raw.append([p,n,key,homes[key],line])
    return dict(documents=len(docs), links=len(local_links), localLinks=local_links, definitions=sum(map(len,defs.values())),
                index=[dict(document=p, identifier=k, **v) for p,dd in defs.items() for k,v in dd.items()],
                missingAnchors=missing, errors=errors, citations=citations, raw=raw)
