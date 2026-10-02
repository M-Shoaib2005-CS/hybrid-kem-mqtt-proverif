#!/usr/bin/env python3
"""Checks every variant against the results of the SAME scenario in the Figure-2 base model
(r0..r8, already run). Any DIFF means that modelling assumption matters."""
import re, subprocess
T,F=True,False
H=["secA","secB","b=>c","inj","c=>bResp","reach_c","reach_b"]
ok5=dict(zip(H,[T,T,T,T,T,F,F]))
BASE={n:ok5 for n in ["r0_baseline","r1_ecdh_broken","r2_kem_broken","r5a1_pub_static_kem_leaked","r5a2_pub_static_ecdh_leaked",
 "r5b1_brk_static_kem_leaked","r5b2_brk_static_ecdh_leaked","r6_static_keys_leak_later","r7_ecdh_later_plus_static_kem","r8_kem_later_plus_static_ecdh"]}
BASE["r5a3_pub_both_static_leaked"]=dict(zip(H,[T,F,F,F,T,F,F]))
BASE["r5b3_brk_both_static_leaked"]=dict(zip(H,[F,T,T,T,F,F,F]))
def classify(b):
    if b.startswith("not event("): b=b[4:]
    if "attacker" in b and "secA" in b: return "secA"
    if "attacker" in b and "secB" in b: return "secB"
    if "inj-event(bAccept" in b: return "inj"
    if "==>" in b and "event(bAccept" in b and ("event(cAccept" in b or "event(cCommit" in b): return "b=>c"
    if "==>" in b and "event(cAccept" in b and "bResp" in b: return "c=>bResp"
    if "==>" not in b and b.startswith("event(cAccept"): return "reach_c"
    if "==>" not in b and b.startswith("event(bAccept"): return "reach_b"
def run(f):
    try: out=subprocess.run(["proverif",f+".pv"],capture_output=True,text=True,timeout=90).stdout
    except subprocess.TimeoutExpired: print("   TIMEOUT",f); return {}
    r={}
    for l in out.splitlines():
        m=re.match(r"^RESULT (.*) is (true|false)\\.$",l)
        if m:
            k=classify(m.group(1))
            if k: r.setdefault(k,[]).append(m.group(2)=="true")
    return {k:all(v) for k,v in r.items()}
bad=0
for v in ["nt","pf","ntpf"]:
    for n,e in BASE.items():
        f=f"{v}_{n}"; r=run(f); d=[k for k in e if r.get(k)!=e[k]]; bad+=len(d)
        print(("ok   " if not d else "DIFF ")+f, "" if not d else {k:(e[k],r.get(k)) for k in d})
print(f"\\n{bad} difference(s)")
