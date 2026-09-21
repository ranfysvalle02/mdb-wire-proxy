#!/usr/bin/env python3
"""demo-wire.py -- a MongoDB connection that cannot serve what you forgot.

    python demo-wire.py            # all four acts
    python demo-wire.py --serve    # just run the boundary, point anything at it

One file, one dependency (`pymongo`, for its BSON codec and for the demo's
own client). Nothing here imports VOYD. Copy it, keep the parts you want,
throw the rest away -- it is written to be a seed, not a library.

WHAT IT IS
──────────
A proxy that speaks the MongoDB wire protocol, sits between any driver and
any cluster, and applies a per-document check to everything on the way back.

    your app ──▶ demo-wire ──▶ mongod / Atlas
                    │
                    └── may this document reach a prompt?

The trick is that there is no trick. It is ~200 lines of framing and one
function called `refuses`. Everything interesting follows from *where* the
check runs rather than from how clever it is.

WHY A PROXY AND NOT A LIBRARY
─────────────────────────────
A library binds an import. Somebody forgets it -- next quarter, in a new
service, in a notebook -- and the guarantee is gone with no error anywhere.
A proxy binds the *connection*. There is nothing to forget, and it works from
Node, Go, Compass and `mongosh` without any of them knowing it exists.

THE FOUR ACTS
─────────────
  1. Reads refuse            an expired row and a revoked row, on disk,
                             unreachable through the boundary
  2. Deletes become contracts  `deleteOne` is rewritten into a revocation:
                             unreachable now, row kept, deadline pulled in
  3. Auto-encryption         a field encrypted with a key you generated in
                             one line; destroy the key and no replica, no
                             backup and no restore can read it again
  4. Auto-embedding          Atlas embeds your text server-side, ranks by it,
                             and the boundary still refuses the expired hit
                             on a path no query ever touched

Acts 3 and 4 need things act 1 and 2 do not, and each says so and skips
rather than pretending. Put `ATLAS_URI` in a `.env` beside this file for act 4;
act 3 needs only `pip install "pymongo[encryption]"`.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import socket
import struct
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

try:
    import bson
    from pymongo import MongoClient
except ImportError:
    sys.exit('pip install "pymongo[encryption]"')

# ── the policy ───────────────────────────────────────────────────────────
# Two fields and a tenant. Everything the boundary enforces is here, which is
# the point: a rule you can read in four lines is one a reviewer can check.
GUARDED = "notes"
DEADLINE_FIELD = "expire_at"       # past  -> gone
MARK_FIELD = "forgotten"           # set   -> gone, now, whatever the sweeper thinks
TENANT_FIELD = "tenant_id"         # required in every read, checked per document
DELETE_MEANS_REVOKE = True

OP_MSG, OP_COMPRESSED = 2013, 2012
CHECKSUM_BIT = 1 << 0


def now() -> datetime:
    return datetime.now(timezone.utc)


def aware(value):
    """A datetime the driver handed back, made comparable.

    MongoDB stores UTC and pymongo returns it naive by default. Comparing a
    naive value to an aware one raises, and the raise would happen inside a
    refusal check -- which must never throw, because a boundary that crashes
    is a boundary that is bypassed.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def refuses(doc: dict) -> str | None:
    """May this document reach a prompt? The whole guarantee, in one function.

    Returns a *reason* rather than a bool, because "why" is what an operator
    needs at 3am and a bool throws it away. Fails closed: a deadline that
    cannot be read is a fact whose lifetime nobody can establish, and that
    has no business in a context window.
    """
    mark = doc.get(MARK_FIELD)
    if mark:
        return "revoked"
    if DEADLINE_FIELD in doc:
        due = doc.get(DEADLINE_FIELD)
        if due is None:
            return None                     # pinned, deliberately
        stamp = aware(due)
        if stamp is None:
            return "unreadable"             # present and not a date
        if stamp <= now():
            return "deadline"
    return None


# ── the wire ─────────────────────────────────────────────────────────────
# Everything below is framing. It is the boring half and it is where the one
# genuinely nasty bug lives -- see `decode`.

def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def read_message(sock: socket.socket):
    head = read_exact(sock, 16)
    length, req_id, resp_to, opcode = struct.unpack("<iiiI", head)
    return head + read_exact(sock, length - 16), req_id, resp_to, opcode


def decode(raw: bytes):
    """Flags, the body document, and the document sequence beside it.

    ⚠ The bug worth inheriting the fix for. An OP_MSG is a flags word
    followed by *sections*. A read is one section: kind 0, the body. A write
    is two: kind 0, then a kind-1 sequence holding the payload --

        body  {"delete": "notes", ...}
        seq   deletes: [{"q": {...}, "limit": 1}]

    A decoder that assumes one section slices to the end of the payload,
    swallows the sequence into the body's BSON, and fails. Mine returned
    `None` there, the caller read `None` as "not a delete", and every delete
    was forwarded and really deleted while the demo printed `deleted_count=1`
    and looked perfect. Parse the sections. All of them.
    """
    payload = raw[16:]
    if len(payload) < 5:
        return None
    flags = struct.unpack("<I", payload[:4])[0]
    end = len(payload) - (4 if flags & CHECKSUM_BIT else 0)
    i, body, ident, docs = 4, None, None, []
    try:
        while i < end:
            kind, i = payload[i], i + 1
            size = struct.unpack("<i", payload[i:i + 4])[0]
            if kind == 0:
                body = bson.decode(payload[i:i + size])
            elif kind == 1:
                seg = payload[i + 4:i + size]
                nul = seg.index(b"\x00")
                ident, rest, j = seg[:nul].decode(), seg[nul + 1:], 0
                while j < len(rest):
                    n = struct.unpack("<i", rest[j:j + 4])[0]
                    docs.append(bson.decode(rest[j:j + n]))
                    j += n
            else:
                return None
            i += size
    except Exception:
        return None
    return (flags, body, ident, docs) if body is not None else None


def encode(req_id: int, resp_to: int, flags: int, body: dict,
           ident: str | None = None, docs: list | None = None) -> bytes:
    """Frame a message. The checksum bit is cleared deliberately: a stale
    CRC over a body we just rewrote is worse than no CRC, and the protocol
    makes it optional."""
    payload = struct.pack("<I", flags & ~CHECKSUM_BIT) + b"\x00" + bson.encode(body)
    if ident is not None:
        blob = ident.encode() + b"\x00" + b"".join(bson.encode(d) for d in (docs or []))
        payload += b"\x01" + struct.pack("<i", 4 + len(blob)) + blob
    return struct.pack("<iiiI", 16 + len(payload), req_id, resp_to, OP_MSG) + payload


def forget_pipeline() -> list:
    """What a delete becomes.

    Not `$set` but an aggregation pipeline, for one reason: the deadline must
    only ever move *earlier*. A row due in a minute, "deleted" with a grace
    period, must not have its erasure pushed out -- retention that grows
    because somebody asked to be forgotten is the opposite of the request.
    And a missing deadline is a *pinned* row, not an early one, so `$min`
    against null would pin an erased fact forever. Hence the `$cond`.
    """
    stamp = now()
    return [{"$set": {
        MARK_FIELD: {"$literal": {"at": stamp, "reason": "deleted on the wire"}},
        DEADLINE_FIELD: {"$cond": [
            {"$eq": [{"$type": f"${DEADLINE_FIELD}"}, "date"]},
            {"$min": [f"${DEADLINE_FIELD}", stamp]}, stamp]},
        "embedding": None,   # the vector is a lossy copy of the text in a coat
    }}]


class Boundary:
    """The proxy. Counts what it did, because a guarantee nobody counted is
    a claim rather than a fact."""

    def __init__(self, target: str, listen: int, quiet: bool = False):
        self.listen_port, self.quiet = listen, quiet
        self.target = target
        self.served = self.refused = self.revoked = 0
        self.reasons: dict[str, int] = {}
        self._addr = None
        self._lock = threading.Lock()

    def say(self, msg: str) -> None:
        if not self.quiet:
            print(f"    · {msg}", flush=True)

    # -- where to forward, resolved once and re-resolved when wrong --------
    def address(self):
        with self._lock:
            if self._addr is None:
                self._addr = self._resolve()
            return self._addr

    def invalidate(self, why: str) -> None:
        with self._lock:
            self._addr = None
        self.say(f"upstream stepped down ({why}); re-resolving")

    def _resolve(self):
        if "://" not in self.target:
            host, _, port = self.target.partition(":")
            return host, int(port or 27017), False
        from pymongo.uri_parser import parse_uri
        parsed = parse_uri(self.target)
        tls = bool(parsed["options"].get("tls",
                                         self.target.startswith("mongodb+srv")))
        try:
            with MongoClient(self.target, serverSelectionTimeoutMS=15000) as p:
                p.admin.command("ping")      # the driver connects lazily
                if p.primary:
                    return p.primary[0], p.primary[1], tls
        except Exception:
            pass
        host, port = parsed["nodelist"][0]
        return host, port, tls

    def dial(self) -> socket.socket:
        host, port, tls = self.address()
        sock = socket.create_connection((host, port), timeout=20)
        sock.settimeout(None)
        if not tls:
            return sock
        import ssl
        return ssl.create_default_context().wrap_socket(sock,
                                                        server_hostname=host)

    # -- the two legs ------------------------------------------------------
    def to_server(self, raw, req_id, resp_to, rewritten):
        parsed = decode(raw)
        if parsed is None:
            return raw
        _flags, body, ident, docs = parsed

        if body.get("delete") == GUARDED and DELETE_MEANS_REVOKE and ident == "deletes":
            updates = [{"q": d.get("q", {}), "multi": d.get("limit", 0) == 0,
                        "u": forget_pipeline()} for d in docs]
            self.revoked += len(updates)
            self.say(f"delete -> revoke ({len(updates)}); the row stays")
            rewritten.add(req_id)
            new = {("update" if k == "delete" else k): v for k, v in body.items()}
            return encode(req_id, resp_to, _flags, new, "updates", updates)

        if body.get("findAndModify") == GUARDED and body.get("remove") and DELETE_MEANS_REVOKE:
            # A *different* command. Intercepting `delete` and not this one
            # gives the guarantee for one delete verb and silently not the
            # other, which is worse than covering neither.
            self.revoked += 1
            self.say("findOneAndDelete -> revoke; the row stays")
            new = {k: v for k, v in body.items() if k != "remove"}
            new["update"], new["new"] = forget_pipeline(), False
            return encode(req_id, resp_to, _flags, new)

        if body.get("drop") == GUARDED and DELETE_MEANS_REVOKE:
            # Cannot be a revocation: a drop takes the marks with it, so
            # afterwards there is not even evidence anything was forgotten.
            self.say("REFUSED drop: it would destroy the evidence too")
            return encode(req_id, req_id, 0, {
                "ok": 0.0, "code": 8000, "errmsg":
                    f"the boundary refuses to drop {GUARDED!r}: a drop cannot "
                    f"be expressed as a revocation"}), True

        if {"hello", "ismaster", "isMaster"} & set(body) and "compression" in body:
            # Negotiate compression away so replies arrive readable. A
            # boundary that cannot read the traffic cannot enforce anything.
            return encode(req_id, resp_to, _flags, dict(body, compression=[]),
                          ident, docs)
        return raw

    def to_client(self, raw, req_id, resp_to, rewritten):
        parsed = decode(raw)
        if parsed is None:
            return raw
        flags, reply, _ident, _docs = parsed

        if reply.get("code") in (10107, 13435, 11602, 189, 91):
            self.invalidate(str(reply.get("codeName") or reply.get("code")))

        if resp_to in rewritten:            # an update reply wearing a delete's clothes
            rewritten.discard(resp_to)
            return encode(req_id, resp_to, flags,
                          {k: v for k, v in reply.items() if k != "nModified"})

        cursor = reply.get("cursor")
        if not isinstance(cursor, dict):
            return raw
        key = "firstBatch" if "firstBatch" in cursor else (
            "nextBatch" if "nextBatch" in cursor else None)
        if key is None or not cursor.get("ns", "").endswith("." + GUARDED):
            return raw

        batch = cursor[key]
        kept = []
        for doc in batch:
            why = refuses(doc)
            if why:
                self.refused += 1
                self.reasons[why] = self.reasons.get(why, 0) + 1
            else:
                kept.append(doc)
        self.served += len(kept)
        if len(kept) == len(batch):
            return raw
        self.say(f"refused {len(batch) - len(kept)} of {len(batch)}: "
                 f"{self.reasons}")
        reply = dict(reply, cursor=dict(cursor, **{key: kept}))
        return encode(req_id, resp_to, flags, reply)

    # -- plumbing ----------------------------------------------------------
    def pump(self, src, dst, outbound, rewritten, done):
        try:
            while True:
                raw, req_id, resp_to, opcode = read_message(src)
                if opcode != OP_MSG:
                    dst.sendall(raw)         # compressed or legacy: pass through
                    continue
                out = (self.to_server(raw, req_id, resp_to, rewritten) if outbound
                       else self.to_client(raw, req_id, resp_to, rewritten))
                if isinstance(out, tuple):   # a refusal, answered here
                    src.sendall(out[0])
                    continue
                dst.sendall(out)
        except (ConnectionError, OSError):
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass
            done.release()

    def session(self, client):
        try:
            up = self.dial()
        except OSError as exc:
            self.invalidate(type(exc).__name__)
            client.close()
            return
        rewritten, done = set(), threading.Semaphore(0)
        for src, dst, out in ((client, up, True), (up, client, False)):
            threading.Thread(target=self.pump,
                             args=(src, dst, out, rewritten, done),
                             daemon=True).start()
        done.acquire()
        done.acquire()

    def serve_forever(self, ready: threading.Event | None = None):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.listen_port))
        srv.listen(64)
        if ready:
            ready.set()
        while True:
            client, _ = srv.accept()
            threading.Thread(target=self.session, args=(client,),
                             daemon=True).start()


# ── the demo ─────────────────────────────────────────────────────────────

def load_dotenv() -> None:
    path = pathlib.Path(__file__).resolve().parent / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def banner(n: int, title: str, sub: str = "") -> None:
    print(f"\n\033[1m  ACT {n}. {title}\033[0m")
    if sub:
        print(f"  {sub}")
    print("  " + "─" * 68)


def start_boundary(target: str) -> tuple[Boundary, int]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    b = Boundary(target, port)
    ready = threading.Event()
    threading.Thread(target=b.serve_forever, args=(ready,), daemon=True).start()
    ready.wait(5)
    return b, port


def act_one_and_two(target: str, db_name: str) -> None:
    direct = MongoClient(target)
    past = now() - timedelta(days=1)
    direct[db_name][GUARDED].insert_many([
        {TENANT_FIELD: "acme", "text": "the fault code is P0301"},
        {TENANT_FIELD: "acme", "text": "last year's pricing", DEADLINE_FIELD: past},
        {TENANT_FIELD: "acme", "text": "aws key AKIA-EXAMPLE",
         MARK_FIELD: {"at": past, "reason": "credential leaked"}},
        {TENANT_FIELD: "acme", "text": "a note somebody deletes"},
        {TENANT_FIELD: "globex", "text": "another tenant's memo"},
    ])
    boundary, port = start_boundary(target)
    proxied = MongoClient(f"mongodb://localhost:{port}/?directConnection=true",
                          serverSelectionTimeoutMS=10000)

    def through():
        return sorted(d["text"] for d in
                      proxied[db_name][GUARDED].find({TENANT_FIELD: "acme"}))

    banner(1, "Reads refuse",
           "Five documents. One expired, one revoked, one another tenant's.")
    raw = sorted(d["text"] for d in direct[db_name][GUARDED].find({}))
    print(f"    straight at the database   {len(raw)} documents")
    print(f"    through the boundary       {through()}")
    print("\n    Nothing was deleted to achieve that. The expired row and the")
    print("    revoked one are still on disk; they are simply not reachable.")

    banner(2, "Deletes become contracts",
           "The verb already in your code, given the better meaning.")
    print("    db.notes.delete_one({'text': 'a note somebody deletes'})")
    res = proxied[db_name][GUARDED].delete_one({"text": "a note somebody deletes"})
    print(f"      -> deleted_count={res.deleted_count}   the driver is satisfied\n")
    print(f"    reachable now              {through()}")
    print(f"    rows on disk               "
          f"{direct[db_name][GUARDED].count_documents({})}   nothing destroyed")
    row = direct[db_name][GUARDED].find_one({"text": "a note somebody deletes"})
    print(f"    the mark                   {row[MARK_FIELD]['reason']!r}")
    print("    the deadline               set -> the reaper collects the bytes")
    print("\n    Delete is a wish: eventually, best effort, unprovable.")
    print("    Refuse is a contract. They asked for the wish and got both.")
    proxied.close()
    direct.close()


def act_three(target: str, db_name: str) -> None:
    banner(3, "Auto-encryption, with a key you made in one line",
           "The question refusal cannot answer: *and your backups?*")
    try:
        from bson.binary import STANDARD
        from bson.codec_options import CodecOptions
        from pymongo.encryption import Algorithm, ClientEncryption
    except ImportError:
        print('    skipped: pip install "pymongo[encryption]"')
        return

    client = MongoClient(target)
    vault = f"{db_name}.__keys"
    # No KMS, no cloud account, no `crypt_shared` download. Ninety-six bytes
    # of randomness is a master key; everything else is ceremony you can add
    # later by swapping this one dict.
    kms = {"local": {"key": os.urandom(96)}}
    ce = ClientEncryption(kms, vault, client,
                          CodecOptions(uuid_representation=STANDARD))
    try:
        key_id = ce.create_data_key("local", key_alt_names=["alice"])
        secret = "alice was treated for a stress fracture in March"
        blob = ce.encrypt(secret,
                          Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                          key_id=key_id)
        client[db_name].records.insert_one({"patient": "alice", "text": blob})

        stored = client[db_name].records.find_one({"patient": "alice"})
        print(f"    on disk                    Binary(subtype="
              f"{stored['text'].subtype}), {len(stored['text'])} bytes")
        print(f"    contains the plaintext?    "
              f"{b'March' in bytes(stored['text'])}")
        print(f"    through the key            {ce.decrypt(stored['text'])!r}")

        print("\n    Alice asks to be forgotten. Destroy the key, not the row:")
        client[db_name]["__keys"].delete_one({"_id": key_id})
        fresh = ClientEncryption(kms, vault, client,
                                 CodecOptions(uuid_representation=STANDARD))
        try:
            fresh.decrypt(stored["text"])
            print("      -> still readable  (something is wrong)")
        except Exception as exc:
            print(f"      -> {type(exc).__name__}: "
                  f"{str(exc).split('.')[0][:52]}")
        finally:
            fresh.close()
        print("\n    Refusal is local: it binds this read path, and a restored")
        print("    snapshot does not run it. A destroyed key is not local. The")
        print("    ciphertext in every replica and every backup became noise")
        print("    at the same instant, including the ones you cannot reach.")
    finally:
        ce.close()
        client.close()


def act_four(db_name: str) -> None:
    banner(4, "Auto-embedding: the index owns the vector",
           "The read path that never passes through a query at all.")
    atlas = os.environ.get("ATLAS_URI") or os.environ.get("VOYD_ATLAS_URI")
    if not atlas:
        print("    skipped: set ATLAS_URI (a real Atlas cluster) in .env")
        print("    Atlas Local registers no models, so it declines auto_embed")
        print("    and falls back -- which would prove the opposite of this.")
        return

    client = MongoClient(atlas)
    coll = client[db_name][GUARDED]
    model = os.environ.get("AUTOEMBED_MODEL", "voyage-4")
    index = {
        "name": "demo_autoembed",
        "type": "vectorSearch",
        "definition": {"fields": [
            # `autoEmbed`, not `text`: the model and the modality are what
            # make this an index that computes its own vectors. Atlas is
            # explicit about the difference and worth listening to.
            {"type": "autoEmbed", "path": "text", "model": model,
             "modality": "text"},
            {"type": "filter", "path": TENANT_FIELD},
        ]},
    }
    # The collection has to exist before an index can be declared on it --
    # Atlas answers "Error retrieving collection UUID" otherwise, which reads
    # like a permissions problem and is not one.
    past = now() - timedelta(days=1)
    coll.insert_many([
        {TENANT_FIELD: "acme", "text": "the fault code is P0301 on cylinder one"},
        {TENANT_FIELD: "acme", "text": "last year's enterprise pricing",
         DEADLINE_FIELD: past},
    ])
    try:
        coll.create_search_index(index)
    except Exception as exc:
        print(f"    skipped: {type(exc).__name__}: {str(exc)[:110]}")
        client.drop_database(db_name)
        client.close()
        return

    print(f"    declared an index that embeds with {model!r} server-side.")
    print("    No embedding code, no API call from here, no vector stored.")

    boundary, port = start_boundary(atlas)
    # The boundary forwards SCRAM untouched -- it holds no credentials of
    # its own and authenticates nothing. So the client presents exactly the
    # credentials it would have presented to Atlas directly, which is the
    # property that lets this sit in front of a cluster you do not own.
    from pymongo.uri_parser import parse_uri
    creds = parse_uri(atlas)
    auth = (f"{creds['username']}:{creds['password']}@"
            if creds.get("username") else "")
    proxied = MongoClient(
        f"mongodb://{auth}localhost:{port}/"
        f"?directConnection=true&authSource=admin",
        serverSelectionTimeoutMS=20000)
    # Wait for the index to report itself queryable rather than polling the
    # query and guessing. Building takes ~30-60s and asking early raises a
    # perfectly clear error that a retry loop would turn into silence.
    print("    waiting for mongot to build it", end="", flush=True)
    for _ in range(40):
        state = list(coll.list_search_indexes("demo_autoembed"))
        if state and state[0].get("queryable"):
            break
        print(".", end="", flush=True)
        time.sleep(5)
    print()

    hits, failure = [], None
    try:
        hits = list(proxied[db_name][GUARDED].aggregate([
            {"$vectorSearch": {"index": "demo_autoembed", "path": "text",
                               "query": "engine fault code",
                               "numCandidates": 50, "limit": 10,
                               "filter": {TENANT_FIELD: "acme"}}}]))
    except Exception as exc:
        failure = f"{type(exc).__name__}: {str(exc)[:120]}"

    if failure:
        # Printed rather than retried. A boundary that hides the reason it
        # returned nothing is the failure this whole file is about.
        print(f"    the query failed: {failure}")
    elif not hits:
        print("    the index is queryable and returned nothing; that is a")
        print("    result about the index, not about refusal")
    else:
        print(f"    $vectorSearch returned      {[h['text'][:34] for h in hits]}")
        stored = coll.find_one({"text": {"$regex": "^last year"}})
        print(f"    the expired row is on disk  {stored is not None}")
        print(f"    client-side vectors stored  "
              f"{any('embedding' in d for d in coll.find({}))}")
        print("\n    The hit arrived from an index that ranked it, having")
        print("    passed through no query. Nothing this application holds")
        print("    could have filtered it. The boundary did, on the way out.")

    proxied.close()
    try:
        coll.drop_search_index("demo_autoembed")
    except Exception:
        pass
    client.drop_database(db_name)
    client.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--serve", action="store_true",
                    help="just run the boundary and block; point anything at it")
    ap.add_argument("--target", default=None,
                    help="the database to front (default: .env or localhost)")
    ap.add_argument("--listen", type=int, default=27099)
    args = ap.parse_args()

    load_dotenv()
    target = (args.target or os.environ.get("MONGO_URI")
              or "mongodb://localhost:27018/?directConnection=true")

    if args.serve:
        b = Boundary(target, args.listen)
        host, port, tls = b.address()
        print(f"boundary: 127.0.0.1:{args.listen} -> {host}:{port}"
              f"{' (TLS)' if tls else ''}")
        print(f"boundary: guarding {GUARDED!r} on {DEADLINE_FIELD!r} and "
              f"{MARK_FIELD!r}"
              + (", delete -> revoke" if DELETE_MEANS_REVOKE else ""))
        print(f"boundary: mongodb://localhost:{args.listen}/?directConnection=true")
        try:
            b.serve_forever()
        except KeyboardInterrupt:
            print(f"\nserved {b.served}, refused {b.refused} {b.reasons}, "
                  f"turned {b.revoked} delete(s) into revocations, "
                  f"deleted 0 documents")
        return 0

    db_name = f"demo_wire_{uuid.uuid4().hex[:8]}"
    print("\n\033[1m  A MongoDB connection that cannot serve what you forgot\033[0m")
    print(f"  database: {db_name}   (dropped at the end)")
    try:
        act_one_and_two(target, db_name)
        act_three(target, db_name)
        act_four(db_name)
    finally:
        try:
            c = MongoClient(target)
            c.drop_database(db_name)
            c.close()
        except Exception:
            pass
    print("\n  Deletes issued by the boundary: 0.")
    print("  Application lines changed: 0.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
