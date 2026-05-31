"""Regression: connect+chat still works; hangup/teardown safe with no call."""
import asyncio, base64, json, sys
from datetime import datetime, timezone
import websockets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption)
from settings import Settings
from webrtc_engine import WebRTCEngine
URL = "ws://127.0.0.1:8013"

def mk():
    x = X25519PrivateKey.generate(); e = Ed25519PrivateKey.generate()
    return {"x25519_private": base64.b64encode(x.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())).decode(),
            "x25519_public": base64.b64encode(x.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode(),
            "ed25519_private": base64.b64encode(e.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())).decode(),
            "ed25519_public": base64.b64encode(e.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode(),
            "created_at": datetime.now(timezone.utc).isoformat()}

class C:
    def __init__(s,n,k,room,cr):
        s.n=n; s.e=WebRTCEngine(n,Settings(security_mode="e2ee"),k); s.r=[]
        s.e.on_message=lambda a,t,v:s.r.append((a,t)); s.e.set_room(room,is_creator=cr); s.ws=None; s.room=room
    async def snd(s,p): await s.ws.send(json.dumps(p))
    async def conn(s):
        s.ws=await websockets.connect(f"{URL}/ws/{s.n}?room={s.room}"); asyncio.ensure_future(s.lis())
    async def lis(s):
        async for raw in s.ws:
            m=json.loads(raw);t=m.get("type");a=m.get("sender","");d=m.get("data") or {}
            if t=="offer": await s.e.handle_offer(a,d,s.snd)
            elif t=="answer": await s.e.handle_answer(d,sender=a)
            elif t=="ice-candidate": await s.e.handle_ice(d,sender=a)
            elif t=="peer_joined": await s.e.add_peer(a,s.snd)
            elif t=="room_state":
                for p in m.get("peers",[]): await s.e.add_peer(p,s.snd)
    def st(s,p): return s.e.pcs.get(p).connectionState if p in s.e.pcs else None

async def main():
    a=C("alice",mk(),"ROOM-R",True); b=C("bob",mk(),"ROOM-R",False)
    await a.conn(); await asyncio.sleep(0.4); await b.conn()
    for _ in range(60):
        await asyncio.sleep(0.3)
        if a.st("bob")=="connected" and b.st("alice")=="connected": break
    print("connected:",a.st("bob"),b.st("alice"))
    await asyncio.sleep(1.5)
    await a.e.send_chat("hi"); await asyncio.sleep(1.2)
    chat_ok = any("hi" in t for _,t in b.r)
    print("chat:",chat_ok,"| bob recv:",b.r)
    # hangup safety (no active call) + end_call_from_peer
    try:
        a.e.hangup(); a.e.end_call_from_peer("bob"); b.e.end_call_from_peer("alice")
        print("hangup/teardown: OK (no crash)")
        tdok=True
    except Exception as ex:
        print("hangup/teardown CRASH:",ex); tdok=False
    print("RESULT:", "PASS" if (a.st("bob")=="connected" and chat_ok and tdok) else "FAIL")
    await a.ws.close(); await b.ws.close()
    sys.exit(0 if (chat_ok and tdok) else 1)
asyncio.run(main())
