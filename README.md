# mdb-wire-proxy

---

# Your database speaks a protocol. You can answer it.

### Three hundred lines between your application and MongoDB, and four things that become possible

---

Delete a document. Then ask your vector index about it.

For up to a full minute, it answers. Not with an error, not with a
stale-cache warning — with a normal, well-scored, well-formed hit, ranked
among the living, indistinguishable from a row that still exists. Nothing is
logged. No counter moves. There is nothing to page on, because from the
database's point of view nothing is wrong: the delete was accepted, the
sweeper is scheduled, everything is behaving exactly as designed.

That minute is measured, not guessed. Insert a row already past its TTL
deadline and time how long MongoDB keeps serving it, twenty times:

```
n=20   min=9.4s   p50=60.0s   p99=60.2s
```

A minute is the *good* case. It is the fastest sweeper in the stack. An S3
lifecycle rule has a minimum granularity of one day. A cleanup cron runs
whenever it last worked.

Usually this does not matter. Nobody is harmed because a deleted row lingers
for forty seconds in a reporting query. But a retrieval scope is not a
reporting query — it is the thing a language model is about to read, and it
will happily quote a document that your compliance team believes is gone.

So the question is not *when will this be deleted?* It is **may this fact
reach a prompt, right now?** And nothing in an ordinary read path was ever
asked.

The usual answer is a filter. Add `expire_at: {$gt: now}` to the query, and
remember to add it to the next query, and the one after that, and the one a
contractor writes in eight months. That is not a guarantee, it is a
convention — and conventions have a famous failure mode: they hold until
they do not, and the day they do not looks exactly like every other day.

Here is a different answer, and the point of this post.

**MongoDB is a protocol before it is a product.** You can sit between your
application and your cluster, speak that protocol fluently, and enforce
whatever you like on the way past. No library, no import, no discipline
required from anyone.

```
your app ──▶ demo-wire.py ──▶ mongod / Atlas
                  │
                  └── may this document reach a prompt?
```

The whole thing is one file. Let me show you what it buys, then exactly how
it works, then every bug I hit building it — because that last part is the
bit you actually want if you are going to steal this.

---

## Why a proxy and not a library

A library binds an **import**. Somebody forgets it — next quarter, in a new
service, in a data scientist's notebook — and the rule is gone with no error
anywhere.

A proxy binds the **connection**. There is nothing to forget. It works from
Node, Go, Java, Compass and `mongosh`, none of which know it exists, and
none of which you had to modify.

Notice what that deletes. If you enforce this in a library, you need a CI
check that nobody bypassed the wrapper, a linter rule, a code-review habit,
and a scanner to find the places somebody already did. All of that is
scaffolding around one import that a human might omit. Move the check to the
wire and every piece of that scaffolding becomes unnecessary — not because
you got stricter, but because **there is no longer a bypass to guard**.

An abstraction that deletes its own guardrails is usually in the right place.

---

## Act one: reads that refuse

Five documents. One has an expired deadline, one carries a "forgotten" mark,
one belongs to another tenant.

```
straight at the database   5 documents
through the proxy          ['a note somebody deletes', 'the fault code is P0301']
```

Nothing was deleted to achieve that. The expired row and the marked one are
still on disk, byte for byte. They are simply not reachable through this
connection — which turns out to matter enormously, because "get this
credential out of prompts *immediately*" and "keep the row for the
investigation" stop being contradictory requirements.

The enforcement is one function:

```python
def refuses(doc: dict) -> str | None:
    """May this document reach a prompt? The whole guarantee."""
    if doc.get(MARK_FIELD):
        return "revoked"
    if DEADLINE_FIELD in doc:
        due = doc.get(DEADLINE_FIELD)
        if due is None:
            return None                  # pinned, deliberately
        stamp = aware(due)
        if stamp is None:
            return "unreadable"          # present, and not a date
        if stamp <= now():
            return "deadline"
    return None
```

Three deliberate choices in nine lines:

It returns a **reason**, not a boolean. "Why" is what somebody needs at 3am,
and a bool throws it away. Those strings end up in a counter, and a counter
is the difference between a guarantee and a claim about one.

It **fails closed**. A deadline that is present but unparseable is a fact
whose lifetime nobody can establish, and that has no business in a context
window. Note that `None` is treated as *pinned* rather than expired, because
those are genuinely different things and conflating them would quietly
delete everything without a deadline.

And it **never raises**. This runs inside a proxy. A boundary that throws is
a boundary that is bypassed.

It costs 128 nanoseconds. Put that beside a 500ms model call: roughly four
million to one. The check has never been the expensive part. Not asking has.

---

## Act two: deletes that become contracts

This is the move I did not expect to be the best one.

Every codebase already contains `deleteOne`. It is written, reviewed,
shipped, forgotten. So intercept it and give it a better meaning:

```
db.notes.delete_one({'text': 'a note somebody deletes'})
  -> deleted_count=1          the driver is perfectly satisfied

reachable now     ['the fault code is P0301']
rows on disk      5           nothing was destroyed
the mark          'deleted on the wire'
the deadline      set -> the TTL reaper collects the bytes on its own schedule
```

The caller asked for a delete. They got something strictly better: the fact
is unreachable *immediately* — not after the next sweep — the row survives
for the audit, and the bytes still go, on the deadline they already had.

**Zero lines changed.** Every existing delete call site in the codebase
becomes immediate, provable, evidence-preserving forgetting.

A caveat that nearly shipped as a hole: `deleteOne` and `findOneAndDelete`
are **different wire commands** (`delete` and `findAndModify`). Intercepting
one and not the other does not give you half a guarantee — it gives you a
false one, which is the only kind that gets trusted. I found this by writing
a three-line probe that tried every destructive verb:

```
via deleteOne            ON DISK          ← intercepted
via findOneAndDelete     REALLY DELETED   ← silently not
```

Both are covered now. And the verbs that *cannot* become a revocation —
`drop`, `dropDatabase`, `renameCollection` — are refused outright with a
readable error, because a drop takes the marks with it and afterwards there
is not even evidence that anything was ever forgotten.

---

## Act three: destroying a key beats deleting a row

Everything above binds *this read path*. A restored snapshot does not run
it. Neither does a DBA with a shell, a replica in another region, or the
backup nobody has opened since March.

So encrypt the field, and treat the key as the thing you destroy.

```python
kms = {"local": {"key": os.urandom(96)}}
```

That is the entire ceremony. Ninety-six bytes of randomness is a master key.
No cloud account, no KMS bill, no Enterprise `crypt_shared` download — and
the same one line becomes AWS, Azure, GCP or KMIP later by changing the
dict, because MongoDB's client-side encryption treats them all as providers.

```
on disk                    Binary(subtype=6), 130 bytes
contains the plaintext?    False
through the key            'alice was treated for a stress fracture in March'

Alice asks to be forgotten. Destroy the key, not the row:
  -> EncryptionError: not all keys requested were satisfied
```

One `delete_one` against the key vault, and the ciphertext in **every**
replica and **every** backup became noise at the same instant — including
the copies you cannot reach and the ones you have forgotten you have.

That is a strictly stronger sentence than "this application will not serve
it." The two mechanisms are not redundant: refusal covers the window before
erasure, and key destruction covers the copies refusal cannot reach.

Worth knowing: this uses **explicit** encryption, which needs no
`mongocryptd` and no `crypt_shared` binary. You call `encrypt()` and
`decrypt()` yourself. Automatic encryption — where the driver does it
transparently from a schema — is lovely and requires an Enterprise download
that is not on PyPI. For a demo, and for a lot of production, explicit is
enough and has one fewer thing to install.

---

## Act four: when the index owns the vector

Atlas can embed your text itself. You declare a model on the index, insert
plain text, and never compute a vector at all:

```json
{"type": "autoEmbed", "path": "text", "model": "voyage-4", "modality": "text"}
```

No embedding code. No API call from your process. No vector field on your
documents. This quietly removes a whole class of bug — a client-side
embedder can drift from whatever the index was built with, and a vector from
last quarter's model is not a worse hit, it is a hit in a *different space*,
which is far harder to notice.

It also produces the purest version of the argument in this post:

```
$vectorSearch returned      ['the fault code is P0301 on cylinder one']
the expired row is on disk  True
client-side vectors stored  False
```

Follow what happened. The application computed nothing. It issued no query
with a filter. The hit arrived from an index that ranked it by relevance and
was asked nothing else. There was **nothing this application held that could
have filtered it** — and the expired document was still refused, on the way
out, microseconds before it became context.

Relevance and permission are different questions. An index only ever answers
the first one. Something has to answer the second, and the way out is the
only place that sees every path.

---

## How it actually works

### The frame

Every MongoDB message is a 16-byte header and a body:

```
 0         4          8           12        16
 ┌─────────┬──────────┬───────────┬─────────┐
 │ length  │ requestId│ responseTo│ opCode  │
 └─────────┴──────────┴───────────┴─────────┘
```

`OP_MSG` (2013) is the only opcode that matters in modern MongoDB. Its body
is a flags word followed by **sections**:

- **kind 0** — the command document: `{"find": "notes", "filter": {…}}`
- **kind 1** — a *named sequence* of documents beside it

Reads are one section. **Writes are two.** This is where the one genuinely
nasty bug lives, so it gets its own heading.

### The bug you should inherit the fix for

A `delete` looks like this on the wire:

```
kind 0   {"delete": "notes", "ordered": true, "$db": "app"}
kind 1   deletes: [{"q": {"_id": 1}, "limit": 1}]
```

A decoder that assumes a single section slices to the end of the payload,
swallows the kind-1 bytes into the body's BSON, and fails to parse.

Mine returned `None` there. The caller read `None` as *"not a delete"*. So
every delete was forwarded and genuinely deleted, the driver was told
`deleted_count=1`, the demo printed a perfect-looking result, and the only
thing that gave it away was a row count of 1 where my assertion expected 2.

That is the whole shape of the danger in this kind of work: a proxy that is
wrong and *quiet*. Parse the sections. All of them.

Two smaller frame rules, both learned the same way:

- **Clear the checksum bit when you rewrite a message.** A stale CRC over a
  body you just changed is worse than no CRC, and the protocol makes it
  optional for exactly this reason.
- **Negotiate compression away in the handshake.** Strip `compression` from
  the `hello` command and replies come back readable. A boundary that cannot
  read the traffic cannot enforce anything, and recompressing every rewritten
  batch is a great deal of work to avoid a demo's worth of bandwidth.

### Turning a delete into a revocation

The rewrite is an aggregation pipeline rather than a `$set`, and every clause
is a bug somebody hit:

```python
[{"$set": {
    "forgotten": {"$literal": {"at": stamp, "reason": "deleted on the wire"}},
    "expire_at": {"$cond": [
        {"$eq": [{"$type": "$expire_at"}, "date"]},
        {"$min": ["$expire_at", stamp]},    # only ever earlier
        stamp]},                            # a pinned row gets a deadline
    "embedding": None,                      # the derived copy goes now
}}]
```

- **`$literal`**, because a caller-supplied reason beginning with `$` would
  otherwise be read as a field path and write something else entirely.
- **`$min`**, because retention that *grows* when somebody asks for erasure
  is the precise opposite of the request.
- **the `$cond`**, because a missing deadline is a *pinned* row, not an early
  one, and `$min` against null keeps the null — which would pin an erased
  fact forever. This is the clause people forget.
- **`embedding: None`**, because a vector is a lossy copy of the text
  wearing a coat, and it should not outlive the thing it encodes.

And the reply needs translating on the way back: the client issued a
`delete` and is entitled to a delete's response shape, so strip the
`nModified` that an update adds.

### Finding the right node, and noticing when it changes

`mongodb+srv://` means three things a raw TCP dial cannot do: the hosts live
in DNS SRV records, the connection must be TLS, and there is no port in the
string. Skip this and your proxy fronts a container on localhost and nothing
anybody runs in production.

Worse, a replica set will happily let you connect to a **secondary**, which
serves reads perfectly and rejects every write with `NotWritablePrimary`. So
resolve the primary — and note that `.primary` is `None` on an undiscovered
topology, because the driver connects lazily. Ping first, or you will
silently select the first node DNS returned and wonder why your fix did not
work.

Then the bit I like most. You do not need a health check to notice a
failover:

```python
if reply.get("code") in (10107, 13435, 11602, 189, 91):
    self.invalidate(...)          # next connection re-resolves
```

Those codes — `NotWritablePrimary`, `PrimarySteppedDown`, and friends —
arrive on the reply the client was getting anyway. A health check is a guess
about the future; that error is the server describing the present, on the
very message that proves it. No timer, no polling a healthy cluster forever
about an event that may never happen, and no window where the proxy knows
and has not acted.

Check inside `writeErrors` too. That is where the code hides on a batched
write, which is to say on exactly the command a proxy like this rewrites.

### Connections

Do **not** pool upstream connections. A MongoDB connection carries
authentication state, sessions, cursors and transactions — share one and you
will hand a cursor to whoever asked second, which is a bug that does not
reproduce and does not error.

One upstream per client, and bound how many exist at once. Past the limit,
**close** rather than queue: a driver retries, and an unbounded backlog is
how a proxy turns a busy minute into an outage.

Also: bind loopback unless you terminate TLS from clients. A plaintext proxy
reachable from the network would carry in the clear every document it just
refused to serve, which is a worse failure than having no proxy at all.

---

## What this is not

It is not a driver. It picks one node and forwards bytes. No read
preference, no load balancing, no retrying a write the client already saw
fail. If you want those, you want a driver, and there is a good one already.

It is not a security boundary against a determined attacker with a database
credential. Anyone who can reach the cluster directly bypasses it entirely —
which is exactly why act three exists, because a destroyed key is not
bypassable by connecting somewhere else.

And it is not production-hardened. It is a correct boundary before it is an
operable one, and you should read the file before you put it anywhere that
matters.

---

## Take the file

`demo-wire.py` is one file and one dependency. It is written to be a **seed**
— copy it, keep the parts you want, delete the rest, rename everything.

```bash
pip install "pymongo[encryption]"

python demo-wire.py                 # all four acts
python demo-wire.py --serve         # just the proxy; point anything at it
```

| act | needs |
|---|---|
| 1 — reads refuse | any `mongod` |
| 2 — deletes become contracts | any `mongod` |
| 3 — key destruction | `pymongo[encryption]`. No KMS, no `crypt_shared` |
| 4 — server-side embedding | a real Atlas cluster in `ATLAS_URI` |

The policy is four constants at the top of the file. Change them and the
whole thing is about your collection instead of mine.

---

## The one sentence

> **An index decides what is relevant. Nothing in your read path was asked
> whether it was allowed.**

Your database speaks a protocol. You are allowed to answer it, and the place
where every read path converges — on the way out — is the only place a rule
cannot be forgotten.

Delete is a wish. Refusal is a contract.

---
---

# Appendix

## A. Every wire command this touches

| command | what happens | why |
|---|---|---|
| `find`, `aggregate`, `getMore` | replies filtered per document | the batch is in `cursor.firstBatch` / `nextBatch` |
| `delete` | rewritten to `update` with a forget pipeline | the row survives; the reply is translated back |
| `findAndModify` + `remove: true` | rewritten to `findAndModify` + `update` | the caller still gets the document back |
| `drop`, `dropDatabase`, `renameCollection` | refused with an error | cannot be expressed as a revocation |
| `hello` / `isMaster` | `compression` stripped | so replies are readable |
| everything else | forwarded byte for byte | fewer bytes touched, fewer bugs invented |

## B. Reading a cursor batch

Replies put documents in one of two places, and you need both:

```python
cursor = reply.get("cursor")
key = "firstBatch" if "firstBatch" in cursor else "nextBatch"
```

`firstBatch` comes back from `find` and `aggregate`. `nextBatch` comes back
from `getMore`, which is how you get the rest — and a proxy that filters only
the first page is a proxy that leaks everything after document 101.

The namespace is in `cursor.ns` as `"db.collection"`, which is the only place
a reply says what it is about. Use it to decide whether the policy applies,
and forward untouched when it does not.

## C. Failover codes worth knowing

| code | name | means |
|---|---|---|
| 10107 | `NotWritablePrimary` | you are talking to a secondary |
| 13435 | `NotPrimaryNoSecondaryOk` | same, with read preference in play |
| 11602 | `InterruptedDueToReplStateChange` | an election happened mid-operation |
| 189 | `PrimarySteppedDown` | it was primary when you started |
| 91 | `ShutdownInProgress` | going away now |

Any of them means your cached address is wrong *now*. Re-resolve on the next
connection rather than retrying the current one — the client is going to
retry anyway, and that is the driver's job, not yours.

## D. Client-side encryption without the Enterprise bits

The confusing part of MongoDB's encryption story is that there are two of
them.

**Automatic** encryption is driver-transparent: you give it a schema, it
encrypts matching fields on write and decrypts on read, and your application
code never sees ciphertext. It requires `crypt_shared` or `mongocryptd` —
an Enterprise download, not on PyPI.

**Explicit** encryption is a function call. You encrypt the value, you store
it, you decrypt it when you read. It needs nothing but
`pip install "pymongo[encryption]"`.

```python
ce = ClientEncryption(kms, f"{db}.__keys", client, codec_options)
key_id = ce.create_data_key("local", key_alt_names=["alice"])
blob = ce.encrypt(secret, Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                  key_id=key_id)
```

Deterministic encryption produces the same ciphertext for the same plaintext,
which means you can still do equality queries on the field. It also means an
observer can see which rows share a value — a real trade, made deliberately.
Use `Random` instead when you do not need to query it.

The key vault is just a collection. **Shredding is a `delete_one`.** That is
the whole feature, and it is why key-per-subject is such a good shape: one
delete, and one person's data is noise everywhere at once.

## E. Server-side embedding, exactly

```python
coll.insert_many([...])                 # the collection must exist FIRST
coll.create_search_index({
    "name": "demo_autoembed",
    "type": "vectorSearch",
    "definition": {"fields": [
        {"type": "autoEmbed", "path": "text",
         "model": "voyage-4", "modality": "text"},
        {"type": "filter", "path": "tenant_id"},
    ]},
})
```

Then query with text rather than a vector:

```python
{"$vectorSearch": {"index": "demo_autoembed", "path": "text",
                   "query": "engine fault code",
                   "numCandidates": 50, "limit": 10,
                   "filter": {"tenant_id": "acme"}}}
```

Four things that cost me time:

1. **The collection must exist before you index it.** Atlas answers "Error
   retrieving collection UUID," which reads like a permissions problem and
   is not one.
2. **It is `type: autoEmbed`, not `type: text`.** Atlas tells you this
   clearly, which is more than most errors manage.
3. **The model list moves.** `voyage-3` was dropped; the current set is
   `voyage-4`, `voyage-4-lite`, `voyage-code-4`, `voyage-code-3`,
   `voyage-4-large`. The server reports the supported set in its own error —
   the most useful error message in this whole exercise.
4. **Atlas Local registers no models at all.** It *declines* an `autoEmbed`
   declaration and falls back to expecting a client-supplied vector, silently.
   If you test this locally you will be testing the opposite of what you
   think.

Also worth knowing: filter fields must be declared in the index definition
to be usable in `$vectorSearch.filter`. Pre-filtering happens *during* the
HNSW traversal rather than on a pre-drawn sample — I swept `numCandidates`
from 50 to 2000 against a filter selecting 5 documents out of 600 and got
all five every time. The widely-repeated advice to scale `numCandidates`
with filter selectivity did not reproduce at that size; it may well bite at
millions, and I have no data there.

## F. Debugging a wire proxy

Build the sniffer before you build the proxy. Ninety lines that forwards
bytes and prints decoded BSON in both directions will answer questions no
amount of reading the spec will:

```python
while True:
    head = read_exact(src, 16)
    length, req_id, resp_to, opcode = struct.unpack("<iiiI", head)
    body = read_exact(src, length - 16)
    dst.sendall(head + body)
    print(opcode, decode_sections(head + body))
```

That is how I learned that writes carry a kind-1 sequence, that
`findOneAndDelete` is `findAndModify` with `remove: true`, and what the
`hello` handshake actually negotiates. Guessing any of those would have cost
more than writing the sniffer did.

And when something goes wrong: **print the error, do not retry it.** My first
version of act four wrapped the query in `except Exception: hits = []` and
looped for five minutes before reporting "the index never became queryable."
The actual error was `Command aggregate requires authentication` — the
proxied client had no credentials, which was a three-second fix hidden
behind a retry loop.

A boundary that hides the reason it returned nothing is the exact failure
this entire pattern exists to prevent. Do not build one by accident while
building one on purpose.

## G. Measured, on a laptop

| claim | number | how |
|---|---|---|
| per-document check | **128ns** p50, 140ns p99 | 30 × 1000 documents, `refuses()` alone |
| that, against a model call | ~**4,000,000:1** | 128ns vs. a 500ms generation |
| TTL sweep interval | p50 **60.0s**, p99 60.2s | 20 expired inserts, timed |
| ciphertext on disk | **130 bytes**, BSON subtype 6 | plaintext absent, checked in the bytes |
| key destroyed → unreadable | `EncryptionError` | one `delete_one` on the key vault |

Every one of these is reproducible by running the file. The first is the one
that surprises people, and the second is why: the check has never been the
expensive part.
