#!/usr/bin/env python3
import re, subprocess
T,F=True,False
H=["secA","secB","b=>c","inj","c=>bResp","reach_c","reach_b"]
def row(*v): return dict(zip(H,v))
ok5=row(T,T,T,T,T,F,F)
P={"r0_baseline":ok5,"r1_ecdh_broken":ok5,"r2_kem_broken":ok5,"r5a1_pub_static_kem_leaked":ok5,"r5a2_pub_static_ecdh_leaked":ok5,"r5a3_pub_both_static_leaked":row(T,F,F,F,T,F,F),
"r5b1_brk_static_kem_leaked":ok5,"r5b2_brk_static_ecdh_leaked":ok5,"r5b3_brk_both_static_leaked":row(F,T,T,T,F,F,F),
"r6_static_keys_leak_later":row(T,F,T,T,T,F,F),"r6l_static_keys_leak_later_late":ok5,
"r4a_ecdh_broken_later":ok5,"r4b_kem_broken_later":ok5,"r4c_both_broken_later":row(F,F,T,T,T,F,F),
"r7_ecdh_later_plus_static_kem":ok5,"r8_kem_later_plus_static_ecdh":ok5,"r9_everything_later":row(F,F,T,T,T,F,F)}
def classify(b):
    if b.startswith("not event("): b=b[4:]
    if "attacker" in b and "secA" in b: return "secA"
    if "attacker" in b and "secB" in b: return "secB"
    if "inj-event(bAccept" in b: return "inj"
    if "==>" in b and "event(bAccept" in b and "event(cAccept" in b: return "b=>c"
    if "==>" in b and "event(cAccept" in b and "bResp" in b: return "c=>bResp"
    if "==>" not in b and b.startswith("event(cAccept"): return "reach_c"
    if "==>" not in b and b.startswith("event(bAccept"): return "reach_b"
def run(f):
    try:
        out=subprocess.run(["proverif",f+".pv"],capture_output=True,text=True,timeout=90).stdout
    except subprocess.TimeoutExpired:
        print("   TIMEOUT",f); return {}
    r={}
    for l in out.splitlines():
        m=re.match(r"^RESULT (.*) is (true|false)\.$",l)
        if m:
            k=classify(m.group(1))
            if k: r.setdefault(k,[]).append(m.group(2)=="true")
    return {k:all(v) for k,v in r.items()}
bad=0
for f,e in P.items():
    r=run(f); print("==",f)
    for k,x in e.items():
        g=r.get(k); o=g==x; bad+=not o
        print(f"   {'ok  ' if o else 'DIFF'} {k:9s} predicted={x!s:5s} got={g}")
print(f"\n{bad} difference(s) from prediction")
