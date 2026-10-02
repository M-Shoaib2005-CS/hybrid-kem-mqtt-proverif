HEADER = r"""(* ============================================================
   Hybrid KEM-MQTT, FOLLOWING Figure 2 of Dong et al. (TCHES 2026).
   Scenario: {title}
   {note}

   Keys: P has static KEM (skP) and static ECDH (xp); B has static KEM (skB) and
   static ECDH (xb); each knows the other's public keys. Ephemerals: KEMu (P),
   KEMv (B), ECDHt (xu, xv).
   Flow (from the figure):
     P->B  ctb=Encaps(pkB), AEAD_K1(pku, gxu)          K1  = KDF(ssb)
     B->P  ctu, ctp, AEAD_K1'(pkv, gxv)               K1' = KDF(ssb,ssp,ssecs,ssu)
     P->B  ctv
     K2 = KDF(ssb,ssp,ssecs,ssu,ssv,ssecdht)
     B->P  confirmation {bdata}
     P->B  confirmation + data
   MY ASSUMPTIONS (the text dump of the figure does not show them): transcript
   hashes are part of the KDF inputs; who sends which confirmation/timestamp;
   secB stands for the broker's timestamp message.
   ============================================================ *)
free c: channel.

type scalar.  type element.
type kemsk.   type kempk.   type kemss.
type key.

fun pubDH(scalar): element.
fun dh(scalar, element): element.
equation forall x: scalar, y: scalar; dh(x, pubDH(y)) = dh(y, pubDH(x)).

fun kpub(kemsk): kempk.
fun encap(kempk, kemss): bitstring.
reduc forall sk: kemsk, m: kemss; decap(sk, encap(kpub(sk), m)) = m.

fun kdf1(kemss): key.
fun kdf2(kemss, kemss, element, kemss, bitstring): key.
fun kdf3(kemss, kemss, element, kemss, kemss, element, bitstring): key.
fun senc(bitstring, key): bitstring.
reduc forall m: bitstring, k: key; sdec(senc(m, k), k) = m.

fun mk1(kempk, element): bitstring [data].
reduc forall a: kempk, b: element; getpku(mk1(a, b)) = a.
reduc forall a: kempk, b: element; getgxu(mk1(a, b)) = b.
fun mk2(kempk, element): bitstring [data].
reduc forall a: kempk, b: element; getpkv(mk2(a, b)) = a.
reduc forall a: kempk, b: element; getgxv(mk2(a, b)) = b.
fun tr1(bitstring, bitstring): bitstring [data].
fun tr3(bitstring, bitstring, bitstring, bitstring, bitstring, bitstring): bitstring [data].

const FINB: bitstring.
const FINP: bitstring.
{extradecl}
{breaks}
free secA: bitstring [private].
free secB: bitstring [private].

event cAccept(bitstring, bitstring, bitstring, bitstring).
event bResp(bitstring, bitstring, bitstring).
event bAccept(bitstring, bitstring, bitstring, bitstring).
event cCommit(bitstring, bitstring, bitstring, bitstring).

query attacker(secA).
query attacker(secB).
{phasequeries}query ctb: bitstring, ctu: bitstring, ctp: bitstring, ctv: bitstring;
  event(bAccept(ctb, ctu, ctp, ctv)) ==> event({evc}(ctb, ctu, ctp, ctv)).
query ctb: bitstring, ctu: bitstring, ctp: bitstring, ctv: bitstring;
  inj-event(bAccept(ctb, ctu, ctp, ctv)) ==> inj-event({evc}(ctb, ctu, ctp, ctv)).
query ctb: bitstring, ctu: bitstring, ctp: bitstring, ctv: bitstring;
  event(cAccept(ctb, ctu, ctp, ctv)) ==> event(bResp(ctb, ctu, ctp)).
(* reachability: "not event(...) is false" means the event IS reachable (good) *)
query ctb: bitstring, ctu: bitstring, ctp: bitstring, ctv: bitstring;
  event(cAccept(ctb, ctu, ctp, ctv)).
query ctb: bitstring, ctu: bitstring, ctp: bitstring, ctv: bitstring;
  event(bAccept(ctb, ctu, ctp, ctv)).

let pub(skP: kemsk, xp: scalar, pkB: kempk, gxb: element) =
  new sku: kemsk;
  new xu: scalar;
  new rb: kemss;
  let pku = kpub(sku) in
  let gxu = pubDH(xu) in
  let ctb = encap(pkB, rb) in
  let ssecs = dh(xp, gxb) in
  let k1 = kdf1(rb) in
  let e1 = senc(mk1(pku, gxu), k1) in
  out(c, (ctb, e1));
  in(c, (ctu: bitstring, ctp: bitstring, e2: bitstring));
  let ssu = decap(sku, ctu) in
  let ssp = decap(skP, ctp) in
  let k1p = kdf2(rb, ssp, ssecs, ssu, {tr1v}) in
  let pkv = getpkv(sdec(e2, k1p)) in
  let gxv = getgxv(sdec(e2, k1p)) in
  let ssecdht = dh(xu, gxv) in
  new rv: kemss;
  let ctv = encap(pkv, rv) in
  out(c, ctv);
  let k2 = kdf3(rb, ssp, ssecs, ssu, rv, ssecdht, {tr3v}) in
  {pin}
  event cAccept(ctb, ctu, ctp, ctv);
  out(c, {pfinal}){pleak}.

let brk(skB: kemsk, xb: scalar, pkP: kempk, gxp: element) =
  in(c, (ctb: bitstring, e1: bitstring));
  let ssb = decap(skB, ctb) in
  let k1 = kdf1(ssb) in
  let pku = getpku(sdec(e1, k1)) in
  let gxu = getgxu(sdec(e1, k1)) in
  new ru: kemss;
  new rp: kemss;
  new skv: kemsk;
  new xv: scalar;
  let ctu = encap(pku, ru) in
  let ctp = encap(pkP, rp) in
  let pkv = kpub(skv) in
  let gxv = pubDH(xv) in
  let ssecdht = dh(xv, gxu) in
  let ssecs = dh(xb, gxp) in
  let k1p = kdf2(ssb, rp, ssecs, ru, {tr1v}) in
  let e2 = senc(mk2(pkv, gxv), k1p) in
  event bResp(ctb, ctu, ctp);
  out(c, (ctu, ctp, e2));
  in(c, ctv: bitstring);
  let ssv = decap(skv, ctv) in
  let k2 = kdf3(ssb, rp, ssecs, ru, ssv, ssecdht, {tr3v}) in
  {bout}
  {bin}
  if sdec(f3, k2) = FINP then
  event bAccept(ctb, ctu, ctp, ctv){bend}.

process
  new skPs: kemsk;
  new skBs: kemsk;
  new xps: scalar;
  new xbs: scalar;
  let pkP = kpub(skPs) in
  let pkB = kpub(skBs) in
  let gxp = pubDH(xps) in
  let gxb = pubDH(xbs) in
  out(c, (pkP, pkB, gxp, gxb));
  ( !pub(skPs, xps, pkB, gxb) | !brk(skBs, xbs, pkP, gxp){mainextra} )
"""
DLOG="(* ECDH broken: attacker can take discrete logs *)\nreduc forall x: scalar; dlog(pubDH(x)) = x.\n"
KBRK="(* KEM broken: attacker can open any ciphertext *)\nreduc forall pk: kempk, m: kemss; kbreak(encap(pk, m)) = m.\n"
PH="query attacker(secA) phase 1.\nquery attacker(secB) phase 1.\n"
EARLY=dict(bdata="(secB sent WITH the confirmation, before P is confirmed)",
  pin="in(c, (f2: bitstring, d2: bitstring));\n  if sdec(f2, k2) = FINB then\n  let sb = sdec(d2, k2) in",
  bout="out(c, (senc(FINB, k2), senc(secB, k2)));", bend="")
LATE=dict(bdata="(secB sent only AFTER P is confirmed)",
  pin="in(c, f2: bitstring);\n  if sdec(f2, k2) = FINB then",
  bout="out(c, senc(FINB, k2));", bend=";\n  out(c, senc(secB, k2))")
def P(x): return "; phase 1;\n  out(c, %s)" % x
DHL="(xu, ssecs)"; KEML="(rb, ssp, ssu, rv)"; ALLL="(xu, ssecs, rb, ssp, ssu, rv)"
M=lambda *a: " | (phase 1; " + "; ".join("out(c, %s)"%x for x in a) + ")"
# name: (title, note, breaks, phasequeries, pleak, mainextra, variant)
BASE=dict(pfinal="(senc(FINP, k2), senc(secA, k2))",bin="in(c, (f3: bitstring, d3: bitstring));",evc="cAccept",
  tr1v="tr1(ctb, e1)",tr3v="tr3(ctb, e1, ctu, ctp, e2, ctv)",extradecl="")
S={
 "r0_baseline":("R0 baseline","",  "", "", "", "", EARLY),
 "r1_ecdh_broken":("R1 ECDH broken during the run","",DLOG,"","","",EARLY),
 "r2_kem_broken":("R2 KEM broken during the run","Static ECDH still authenticates: authentication is hybrid here.",KBRK,"","","",EARLY),
 "r3_both_broken":("R3 both broken during the run (sanity: must FAIL)","",DLOG+KBRK,"","","",EARLY),
 "r5a1_pub_static_kem_leaked":("R5a1 publisher static KEM key leaked","",  "","","", " | out(c, skPs)",EARLY),
 "r5a2_pub_static_ecdh_leaked":("R5a2 publisher static ECDH key leaked","","","","", " | out(c, xps)",EARLY),
 "r5a3_pub_both_static_leaked":("R5a3 both publisher static keys leaked","","","","", " | out(c, (skPs, xps))",EARLY),
 "r5b1_brk_static_kem_leaked":("R5b1 broker static KEM key leaked","","","","", " | out(c, skBs)",EARLY),
 "r5b2_brk_static_ecdh_leaked":("R5b2 broker static ECDH key leaked","","","","", " | out(c, xbs)",EARLY),
 "r5b3_brk_both_static_leaked":("R5b3 both broker static keys leaked","","","","", " | out(c, (skBs, xbs))",EARLY),
 "r6_static_keys_leak_later":("R6 all four static keys leak after the sessions","",  "",PH,"",M("(skPs, xps, skBs, xbs)"),EARLY),
 "r6l_static_keys_leak_later_late":("R6l as R6 but secB sent only after P is confirmed","","",PH,"",M("(skPs, xps, skBs, xbs)"),LATE),
 "r4a_ecdh_broken_later":("R4a ECDH (ephemeral + static) broken after the session","","",PH,P(DHL),"",EARLY),
 "r4b_kem_broken_later":("R4b all KEM secrets broken after the session","","",PH,P(KEML),"",EARLY),
 "r4c_both_broken_later":("R4c everything broken after the session (sanity: must FAIL)","","",PH,P(ALLL),"",EARLY),
 "r7_ecdh_later_plus_static_kem":("R7 ECDH broken later + static KEM keys leaked later","Ephemeral KEMs should still protect.","",PH,P(DHL),M("(skPs, skBs)"),LATE),
 "r8_kem_later_plus_static_ecdh":("R8 KEM broken later + static ECDH keys leaked later","Ephemeral ECDH should still protect.","",PH,P(KEML),M("(xps, xbs)"),LATE),
 "r9_everything_later":("R9 everything leaks later (sanity: must FAIL)","","",PH,P(ALLL),M("(skPs, xps, skBs, xbs)"),LATE),
}
for n,(t,note,br,pq,pl,me,v) in S.items():
    open(n+".pv","w").write(HEADER.format(title=t,note=note,breaks=br,phasequeries=pq,pleak=pl,mainextra=me,
        bdata=v["bdata"],pin=v["pin"],bout=v["bout"],bend=v["bend"],**BASE))
print(len(S),"files")

# ------------- variants: no transcript (nt), publisher-first confirmation (pf), both (ntpf)
PF=dict(bdata="(publisher confirms first; secB sent only after P is confirmed)",
  pin="event cCommit(ctb, ctu, ctp, ctv);\n  out(c, senc(FINP, k2));\n  in(c, (f2: bitstring, d2: bitstring));\n  if sdec(f2, k2) = FINB then\n  let sb = sdec(d2, k2) in",
  bout="", bend=";\n  out(c, (senc(FINB, k2), senc(secB, k2)))")
PFB=dict(pfinal="senc(secA, k2)",bin="in(c, f3: bitstring);",evc="cCommit")
NT=dict(tr1v="NOTR",tr3v="NOTR",extradecl="const NOTR: bitstring.\n")
SUBSET=["r0_baseline","r1_ecdh_broken","r2_kem_broken","r5a1_pub_static_kem_leaked","r5a2_pub_static_ecdh_leaked",
 "r5a3_pub_both_static_leaked","r5b1_brk_static_kem_leaked","r5b2_brk_static_ecdh_leaked","r5b3_brk_both_static_leaked",
 "r6_static_keys_leak_later","r7_ecdh_later_plus_static_kem","r8_kem_later_plus_static_ecdh"]
VARS={"nt":(NT,None),"pf":(PFB,PF),"ntpf":({**PFB,**NT},PF)}
for vn,(extra,vv) in VARS.items():
    for n in SUBSET:
        t,note,br,pq,pl,me,v=S[n]
        v2=vv if vv else v
        kw=dict(BASE); kw.update(extra)
        open(vn+"_"+n+".pv","w").write(HEADER.format(title=vn.upper()+" variant of "+t,note=note,breaks=br,phasequeries=pq,pleak=pl,mainextra=me,
            bdata=v2["bdata"],pin=v2["pin"],bout=v2["bout"],bend=v2["bend"],**kw))
print("variants done")
