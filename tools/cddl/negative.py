#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Negative examples: instances the CDDL schema must reject.

Every case except the extension field must print 'rejected'.
"""
import os, sys
sys.argv = ["x"]
_here = os.path.dirname(os.path.abspath(__file__))
__file__ = os.path.join(_here, "maxsize.py")
exec(open(__file__).read().split("rows, failures")[0])
cases = {
 "Passport, 129 permits": ("Passport", [pp_head, {**pp_rest, 7: [[B(16),B(8),B(8)]]*129}, SIG]),
 "Get root change with device": ("Get", {0:3,1:B(32),2:3,3:B(16)}),
 "Command lossy with credit": ("Command", {1:1,3:2,4:5}),
 "Refusal code 1 with nonce": ("Refusal", {0:28,1:B(32),2:B(16),3:B(16),4:B(32),5:1,7:B(16)}),
 "Hello version 0": ("Hello", {0:1,1:[0],2:B(16),3:B(32),4:1,5:1,6:B(16)}),
 "JoinSealed with SLH signature": ("JoinSealed", {1:P256,2:"x",3:B(32),5:SIG_PQ}),
 "Reply ct 36 bytes": ("Reply", {0:27,1:B(32),2:B(16),3:B(16),4:B(32),5:B(36)}),
 "PairSealed ct 292 bytes": ("PairSealed", {0:43,1:B(292)}),
 "Publication with SLH signature": ("Publication", [common["Publication"][1][0], B(100), SIG_PQ]),
 "Unknown critical field 9 in Hello": ("Hello", {0:1,1:[1],2:B(16),3:B(32),4:1,5:1,6:B(16),9:0}),
 "Extension field 300 in Hello": ("Hello", {0:1,1:[1],2:B(16),3:B(32),4:1,5:1,6:B(16),300:0}),
 "HaltProof kind 6 with one sig": ("HaltProof", halt(6, rc_head, [SIG])),
 "seg 1023": ("Publication", [{**common['Publication'][1][0], 10:[5000,B(32),1023]}, B(100), SIG]),
 "gen 0": ("SealClaim", [{1:B(32),2:B(16),3:0,4:XWING}, SIG]),
 "RelayTicket depth 16": ("RelayTicket", [{**common["RelayTicket"][1][0], 6: 16}, SIG]),
 "RelayRefusal with bus and alias": ("RelayRefusal", {0:11,1:B(32),2:B(32),3:1,4:B(16)}),
 "RelayHello with both sides": ("RelayHello", {**plain_msgs["RelayHello(device)"], 8:P256}),
 "Relayed control of kind 17": ("Relayed", {0:19,1:1,2:B(16),5:17,6:1,9:B(32),10:B(100)}),
 "Relayed publication without depth": ("Relayed", {0:19,1:3,2:B(16),4:B(16),6:1,9:B(32),10:B(100)}),
 "Relayed body 16281": ("Relayed", {0:19,1:6,2:B(16),9:B(32),10:B(16281)}),
 "Call enc 5249": ("Call", [{1:B(32),2:B(32),3:B(16),4:B(16),5:B(16),6:1,7:1,8:1,9:B(5249)}, SIG]),
}
for n,(rule,v) in cases.items():
    try: ok,_=validate(rule,v)
    except AssertionError: ok='encoder refused'
    print(f"{n:40} {'accepted' if ok is True else 'rejected' if ok is False else ok}")
import cbor2, subprocess, tempfile, os
def raw(rule, data):
    with tempfile.TemporaryDirectory() as d:
        sp=os.path.join(d,'s.cddl'); open(sp,'w').write(f"start = {rule}\n"+open(SCHEMA).read())
        ip=os.path.join(d,'i.cbor'); open(ip,'wb').write(data)
        r=subprocess.run(['cddl',sp,'validate',ip],capture_output=True,text=True)
        return r.returncode==0 and not [l for l in (r.stdout+r.stderr).splitlines() if 'Unused rule' not in l]
base={0:1,1:[1],2:B(16),3:B(32),4:1,5:1,6:B(16)}
for n,v in {"float in extension field":1.5,"negative int in extension":-1,"bool in extension":True,"2^53 in extension":2**53}.items():
    print(f"{n:40} {'accepted' if raw('Hello', cbor2.dumps({**base,300:v})) else 'rejected'}")
