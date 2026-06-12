#!/usr/bin/env python3
"""License Auditor — detect GPL contamination in MIT projects. 0 tokens."""
import os, re, json, subprocess
from datetime import datetime, timezone, timedelta
TZ_CN = timezone(timedelta(hours=8))

GPL_LIKE = {'GPL','LGPL','AGPL','GPL-2.0','GPL-3.0','LGPL-2.1','AGPL-3.0'}
VIRAL_RISK = {'MIT':'GPL','Apache-2.0':'GPL-2.0','BSD':'GPL'}

def audit_deps(dir_path):
    findings = []
    proj_license = _detect_project_license(dir_path)
    if not proj_license: return findings

    deps = _find_dep_files(dir_path)
    for dep_file in deps:
        deps_list = _parse_deps(dep_file)
        for pkg, version in deps_list[:20]:  # Limit API calls
            lic = _get_package_license(pkg, dep_file)
            if lic and lic.upper() in GPL_LIKE:
                findings.append({
                    "rule":"gpl-contamination",
                    "severity":"critical",
                    "detail":f"依赖 {pkg} ({lic}) 可能污染 {proj_license} 项目"
                })
    return findings

def _detect_project_license(dir_path):
    for f in ['LICENSE','LICENSE.md','LICENSE.txt']:
        p = os.path.join(dir_path, f)
        if os.path.exists(p):
            with open(p,'r') as fh: c = fh.read()
            for lic in ['MIT','Apache','BSD','GPL','ISC']:
                if lic in c: return lic
    return None

def _find_dep_files(dir_path):
    deps = []
    for f in ['requirements.txt','package.json','go.mod']:
        p = os.path.join(dir_path, f)
        if os.path.exists(p): deps.append(p)
    return deps

def _parse_deps(path):
    pkgs = []
    fn = os.path.basename(path)
    with open(path,'r') as f:
        c = f.read()
    if fn == 'requirements.txt':
        for l in c.split('\n'):
            l=l.strip().split('#')[0]
            if l and not l.startswith('-'):
                p = re.split(r'[<>=!~\[\s]',l)[0].strip().lower()
                if p: pkgs.append((p,''))
    elif fn == 'package.json':
        try:
            d = json.loads(c)
            for k in list(d.get('dependencies',{}).keys())[:20]:
                pkgs.append((k,d['dependencies'][k]))
        except: pass
    return pkgs

def _get_package_license(pkg, dep_file):
    fn = os.path.basename(dep_file)
    try:
        if fn == 'requirements.txt':
            r = subprocess.run(['curl','-s','--max-time','8','--proxy','http://127.0.0.1:15236',
                f'https://pypi.org/pypi/{pkg}/json'],capture_output=True,text=True,timeout=12)
            d = json.loads(r.stdout) if r.stdout.strip() else {}
            return d.get('info',{}).get('license','')
        elif fn == 'package.json':
            r = subprocess.run(['curl','-s','--max-time','8','--proxy','http://127.0.0.1:15236',
                f'https://registry.npmjs.org/{pkg}/latest'],capture_output=True,text=True,timeout=12)
            d = json.loads(r.stdout) if r.stdout.strip() else {}
            return d.get('license','')
    except: pass
    return None

def main():
    import argparse; ap = argparse.ArgumentParser(); ap.add_argument('--dir',required=True); ap.add_argument('--output',default='license_audit.json')
    args=ap.parse_args()
    findings = audit_deps(args.dir)
    out={"auditor":"license-auditor","timestamp":datetime.now(TZ_CN).isoformat(),"findings":findings}
    os.makedirs('output',exist_ok=True)
    with open(args.output,'w') as f: json.dump(out,f,ensure_ascii=False,indent=2)
    for f in findings: print(f"  [{f['severity']}] {f['detail']}",file=__import__('sys').stderr)
    print(f"{len(findings)} license issues | {args.output}",file=__import__('sys').stderr)

if __name__=='__main__': main()
