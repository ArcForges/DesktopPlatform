# SPDX-License-Identifier: AGPL-3.0-only
"""Compare every current work-package graph representation and its schedule."""

from design_corpus import cells, lines, load
import re

INACTIVE = {'20', '27', '29'}

def graph(root, docs=None):
    docs=load(root) if docs is None else docs
    errors=[]
    index=docs['docs/planning/work-packages/README.md']
    sequence=docs['docs/planning/implementation-sequence.md']
    forward={};phase={};reverse={};packages={}
    ids=lambda value:set(re.findall(r'`(\d{2})`',value))
    for line in sequence.split('## 9. ',1)[1].splitlines():
        m=re.match(r'^\| (\d{2}) \| (.*) \|$',line)
        if m:
            if m[1] in forward:errors.append(['duplicate forward',m[1]])
            forward[m[1]]=ids(m[2])
    for line in index.split('## Downstream dependency index',1)[0].splitlines():
        cs=cells(line)
        if len(cs)==3 and re.fullmatch(r'\d{2}',cs[0]):
            if cs[0] in INACTIVE:
                if ids(cs[2]):errors.append(['inactive phase edges',cs[0]])
                continue
            if cs[0] in phase:errors.append(['duplicate phase',cs[0]])
            phase[cs[0]]=ids(cs[2])
    for line in index.split('## Downstream dependency index',1)[1].split('## Deferred-gate scheduling',1)[0].splitlines():
        cs=cells(line)
        if len(cs)==2 and re.fullmatch(r'\d{2}',cs[0]):
            if cs[0] in reverse:errors.append(['duplicate reverse',cs[0]])
            reverse[cs[0]]=ids(cs[1])
    for p,text in docs.items():
        numbers=[m[1] for n,l in lines(text) if (m:=re.match(r'^## (\d+(?:\.\d+)*)(?:\.)?\s',l))]
        if len(numbers)!=len(set(numbers)):errors.append([p,'duplicate numbered section',numbers])
        m=re.match(r'docs/planning/work-packages/(\d{2})-',p)
        if not m:continue
        if m[1] in INACTIVE:
            for line in text.splitlines():
                if re.match(r'^(?:> Upstream:|\*\*(?:Upstream|Downstream):\*\*)',line) and ids(line):
                    errors.append([p,'inactive package edges'])
            continue
        key=m[1]
        if key in packages:errors.append([p,'duplicate package identifier',key])
        packages[key]=p
        if set(numbers)!=set(str(i) for i in range(1,10)):errors.append([p,'mandatory sections',numbers])
        header=next((l for l in text.splitlines() if l.startswith('> Upstream:')),None)
        if not header or 'Downstream:' not in header:errors.append([p,'missing graph header']);continue
        hu,hd=header.split('Downstream:',1)
        try:
            dep=text.split('## 9. ',1)[1].split('\n## ',1)[0]
            su,sd=dep.split('**Downstream:**',1)
            evidence=text.split('## 7. ',1)[1].split('\n## ',1)[0]
        except (IndexError,ValueError):errors.append([p,'missing dependency/evidence section']);continue
        up,down=ids(su),ids(sd)
        if ids(hu)!=up or ids(hd)!=down:errors.append([p,'header/dependency mismatch'])
        if up!=forward.get(key):errors.append([p,'forward mismatch'])
        if down!=reverse.get(key):errors.append([p,'downstream mismatch'])
        rows=[l for l in evidence.splitlines() if l.startswith('|') and f'#rule-wp-{key}.90)' in l]
        if len(rows)!=1:errors.append([p,'owned .90 evidence rows',len(rows)])
    if forward!=phase:errors.append(['forward/phase mismatch'])
    if set(forward)!=set(packages) or set(reverse)!=set(packages):errors.append(['node sets differ'])
    for key, deps in forward.items():
        if not deps<=forward.keys():errors.append([key,'inactive producer'])
        if reverse.get(key)!={k for k,v in forward.items() if key in v}:errors.append([key,'reverse is not transpose'])
    s=re.search(r'^Serial execution: ([\d, ]+)\.',sequence,re.M)
    order=s[1].split(', ') if s else []
    if len(order)!=len(set(order)) or set(order)!=set(forward):errors.append(['serial node set/order'])
    pos={v:n for n,v in enumerate(order)}
    for k, values in forward.items():
        for v in values:
            if pos.get(v,999)>=pos.get(k,-1):errors.append([k,'producer ordered later',v])
    if f'All {len(forward)} active packages' not in sequence:errors.append(['declared node count'])
    edges=sum(map(len,forward.values()))
    if f'Total active dependency edges: {edges}.' not in sequence:errors.append(['declared edge count'])
    if 'WP42.11 precedes 42.10.' not in sequence:errors.append(['commerce substep order missing'])
    return {'nodes':len(forward),'edges':edges,'order':order,
            'forward':{k:sorted(v) for k,v in forward.items()},
            'reverse':{k:sorted(v) for k,v in reverse.items()},
            'packages':packages,'errors':errors}
