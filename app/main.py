"""FastAPI application (spec Section 18).

Local, unauthenticated by default (``uvicorn app.main:app``). Needs the ``[api]``
extra.

Two layers are kept separate on purpose:
  * HTTP status  - transport-level "could I process this request?"
  * policy outcome - a ``PolicyOutcome`` in the response body

A policy-blocked assessment returns HTTP 422 with ``status="POLICY_BLOCKED"`` and
the ``policy_decision`` in the body - never HTTP 200 with empty findings.
``human_review_required`` is a workflow flag inside a COMPLETED (HTTP 200) body,
not an error.

There is **no endpoint that changes knowledge content**. ``/v1/knowledge/reindex``
only re-derives the FTS index from the already-verified read-only knowledge root.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import logging
import sqlite3
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.config import Settings
from app.ingestion.validator import Level, validate_markdown
from app.llm.factory import get_client
from app.models.answer import AnswerPatch
from app.models.assessment import AssessmentInput, SafeTest
from app.models.report import AssessmentReport, ReportStatus
from app.policy.safe_test import load_safe_test_templates
from app.retrieval.index import ReindexReport, reindex_atomic
from app.reviewer.answers import AnswerValidationError, apply_patch
from app.reviewer.report import build_report, render_text
from app.reviewer.rule_loader import RuleCatalogue, load_rules
from app.storage.db import connect
from app.storage.repository import ChunkRepository

app = FastAPI(title="Security Knowledge OS", version="0.1.0")
_logger = logging.getLogger(__name__)

# Codex cross-review finding #4 (round 4, 2026-09-12), reproduced exactly as
# reported: POSTing two million bytes of whitespace padding around a tiny
# valid AssessmentInput returned 200 - pydantic's canonical serialization
# drops insignificant JSON whitespace, so AssessmentInput's total-size
# model_validator (round 3) only ever sees the small PARSED object, never the
# actual wire size the server had to receive and parse. Counting bytes as
# they stream in (rather than trusting a Content-Length header, which
# chunked transfer-encoding omits) bounds memory/CPU spent on the request
# body regardless of what it deserializes to.
_MAX_BODY_BYTES = 1_000_000


class _MaxBodySizeMiddleware:
    """Raw ASGI middleware: reject a request body over `_MAX_BODY_BYTES`
    before FastAPI/pydantic - or any handler - ever sees it. Added via
    `app.add_middleware()` (not `@app.middleware("http")`, which would need
    to fully buffer the body itself via `Request.body()` to inspect it -
    defeating the point).

    Codex#13 (round 8, 2026-09-12) added a Content-Length precheck for a
    BODYLESS endpoint (one whose handler takes no Request/body parameter
    and so never calls `receive()` at all) - fixed the ordinary case, but
    Codex#10 (round 9, 2026-09-12), reproduced exactly as reported: a
    CHUNKED request (which omits Content-Length entirely) to that same
    bodyless endpoint was still never counted by anything, since nothing
    downstream ever called `receive()` to trigger a per-chunk count.
    Eagerly draining and counting the FULL body itself, for every request,
    before the app ever runs, closes this regardless of Content-Length
    vs. chunked encoding and regardless of whether the handler underneath
    ever reads the body - the drained messages are buffered and replayed
    through a substitute `receive()` so a handler that DOES read the body
    still sees it normally."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Codex#13 (round 8, 2026-09-12), reproduced exactly as reported: a
        # POST to /v1/knowledge/reindex (a bodyless endpoint - its handler
        # takes no Request/body parameter) with an oversized body returned
        # 200. `_limited_receive` below only counts bytes if the DOWNSTREAM
        # app ever calls `receive()`; an endpoint that never reads the body
        # never triggers it. A `Content-Length` header states the size
        # up front, before any bytes even need to be read - reject on that
        # alone as a fast, general pre-check that does not depend on
        # whether the endpoint underneath happens to read its body. (A
        # client using chunked transfer-encoding, which omits
        # Content-Length, is not covered by this pre-check specifically -
        # `_limited_receive`'s streaming count below is what still catches
        # that for any endpoint that DOES read the body; an endpoint that
        # reads neither the header nor the body is documented as this
        # project's own localhost/no-auth MVP scope, not a gap this
        # middleware alone can close for every conceivable client.)
        for key, value in scope.get("headers") or ():
            if key == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = None
                if declared is not None and declared > _MAX_BODY_BYTES:
                    await self._reject_413(send)
                    return
                break

        # Codex#10 (round 9, 2026-09-12), reproduced exactly as reported:
        # the Content-Length precheck above fixed the ordinary case, but a
        # CHUNKED request (which omits Content-Length entirely) to a
        # bodyless endpoint - one whose handler takes no Request/body
        # parameter and so never calls receive() at all - was never
        # counted by anything: the old `_limited_receive` wrapper only
        # counted bytes on receive() calls the downstream app actually
        # made. Eagerly draining and counting the FULL body ourselves,
        # for every request, before the app ever runs, removes that
        # dependency entirely - it works the same whether the client used
        # Content-Length or chunked encoding, and whether or not the
        # handler underneath ever reads the body. The drained messages are
        # buffered and replayed through a substitute `receive()` so a
        # handler that DOES read the body still sees it normally.
        buffered: list[Any] = []
        seen = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] != "http.request":
                break
            seen += len(message.get("body") or b"")
            if seen > _MAX_BODY_BYTES:
                await self._reject_413(send)
                return
            if not message.get("more_body", False):
                break

        async def _replay_receive() -> Any:
            if buffered:
                return buffered.pop(0)
            return await receive()

        await self.app(scope, _replay_receive, send)

    @staticmethod
    async def _reject_413(send: Any) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {"type": "http.response.body", "body": b'{"detail":"request body too large"}'}
        )


app.add_middleware(_MaxBodySizeMiddleware)

# Codex cross-review finding #10 (2026-09-11): the in-memory store had no size
# bound at all. Accepted as in-memory for the MVP (spec Section 18, localhost
# scope), but unbounded growth from repeated /v1/assessments or /answers calls
# is still a resource-exhaustion vector on its own. Simple FIFO cap - not a
# full LRU/expiry policy, but it turns "unbounded" into "bounded" cheaply.
#
# Codex#8 (round 8, 2026-09-12), reproduced exactly as reported: an
# entry-COUNT cap alone bounds nothing meaningful about actual memory -
# AssessmentInput's own total-size cap (_MAX_SERIALIZED_BYTES, 300_000)
# means 5,000 entries near that limit retain ~1.5 GB from the inputs
# alone, before the AssessmentReport half of each entry, the Pydantic
# object overhead, and any LLM raw-result storage are even counted. A
# byte-weighted budget bounds what actually matters (memory), with the
# entry count as a secondary belt-and-suspenders cap for the common case
# of many small entries.
_MAX_STORE_ENTRIES = 5000
_MAX_STORE_BYTES = 50_000_000  # ~50 MB
_STORE: dict[str, tuple[AssessmentInput, AssessmentReport]] = {}
_STORE_ENTRY_BYTES: dict[str, int] = {}
_STORE_TOTAL_BYTES = 0

# Codex cross-review finding #6, part 2 (round 2, 2026-09-11): resubmitting
# the SAME (non-no-op) patch against the SAME parent repeatedly used to create
# a brand-new assessment + store entry every time - each call is a full
# re-assessment (LLM/provider cost too, when configured) for a result that is
# byte-for-byte identical to one already computed. Cached by
# (parent_assessment_id, resulting merged-input hash) -> the assessment_id
# that patch already produced, so a repeat returns the existing result instead
# of paying to recompute (and store) a duplicate. Bounded the same way as
# _STORE; a cache miss (evicted or never seen) just re-runs, same as before -
# this is a cost/dedup optimization, not a correctness requirement.
_MAX_ANSWER_CACHE_ENTRIES = 5000
_ANSWER_CACHE: dict[tuple[object, ...], str] = {}

# Codex#5 (round 12, 2026-09-13), reproduced exactly as reported: the
# answer-cache dedup above only catches a repeat of the SAME patch against
# the SAME parent - always patching the newest CHILD with a different
# value each time (e.g. toggling one field back and forth) changes the
# cache key on every call, so a chain of otherwise-legitimate-looking
# requests can trigger an unbounded number of real provider calls over
# time, with nothing bounding the chain's LENGTH the way
# _MAX_CONCURRENT_ASSESSMENTS bounds concurrent width. A full auth +
# per-principal rate/token/monetary budget system (Codex's own suggested
# fix, same as round 9's identical "out of scope" note above) is a real
# feature, not a bug fix. What IS a proportionate bug fix: every
# assessment already carries its own chain depth for free (`revision`,
# incremented once per `/answers` call - see submit_answers() below), so
# capping it costs no new state and closes the unbounded-LENGTH case
# outright; a caller past the cap starts a fresh assessment instead
# (itself still bounded by the concurrency/store caps above). This does
# not bound total SPEND across many independent chains, or over time -
# only the length of any one chain; the residual, disclosed risk
# (unbounded aggregate provider spend without authentication) exists only
# when an operator has opted into a real, paid LLM provider at all - the
# default `llm_provider` is `none` (fully offline, zero cost) - see
# PUBLICATION_MANIFEST.md's Known/accepted risks table.
_MAX_ANSWER_CHAIN_DEPTH = 100

# Codex#6 (round 9, 2026-09-12), reproduced exactly as reported: the loopback
# checks stop remote and browser-CSRF callers, but any local OS user/process
# could still issue unlimited unique assessments (each a real rule-load, and
# a real provider call when an LLM is configured) or oscillating answer
# chains with nothing bounding total concurrent work - store size caps and
# identical-request dedup do not limit request RATE or CONCURRENCY. A full
# auth + token-budget system (Codex's own suggested fix) is a real feature,
# not a bug fix, and is out of scope here - this is the narrower, concrete
# control available without one: a hard cap on how many assessments can be
# IN FLIGHT at once, rejecting immediately (429) rather than queuing, so a
# burst of concurrent requests cannot occupy the whole worker pool or drive
# unbounded concurrent provider spend. It does not bound total request RATE
# over time or per-request cost - only concurrency.
_MAX_CONCURRENT_ASSESSMENTS = 10
_ASSESSMENT_SEMAPHORE = threading.Semaphore(_MAX_CONCURRENT_ASSESSMENTS)

# Codex#6 (round 10, 2026-09-13), reproduced exactly as reported:
# reindex_atomic()'s own flock() (app/retrieval/index.py) serializes
# concurrent rebuilds, but it BLOCKS - a burst of concurrent
# POST /v1/knowledge/reindex requests (this endpoint is unauthenticated by
# design, spec §18 localhost scope) each occupy an AnyIO worker thread
# waiting on that lock instead of getting an immediate answer, and each
# queued request still eventually performs a full, expensive rebuild once
# admitted. A nonblocking admission gate at the endpoint - the same shape
# as _ASSESSMENT_SEMAPHORE above - rejects with 429 immediately instead of
# occupying a worker thread, mirroring the existing assessment control.
_REINDEX_LOCK = threading.Lock()

# Codex#5 (round 5, 2026-09-12), reproduced exactly as reported: with
# `_MAX_STORE_ENTRIES = 1`, 32 threads calling `_store_put` concurrently (each
# FastAPI sync endpoint runs in its own worker thread) produced
# `RuntimeError("dictionary changed size during iteration")` and `KeyError`
# from the unguarded assign-then-evict sequence below. `_answer_lock_for`
# (round 4) already serializes the compute-and-store critical section for a
# given cache key, but the plain assignment/eviction here races across
# *different* keys/callers regardless of that. A single lock per dict is
# sufficient (these are cheap dict operations, not the assessment compute
# itself) and keeps the FIFO-eviction contract intact under concurrency.
_STORE_GUARD = threading.Lock()
_ANSWER_CACHE_GUARD = threading.Lock()


def _entry_size(entry: tuple[AssessmentInput, AssessmentReport]) -> int:
    inp, report = entry
    return len(inp.model_dump_json().encode("utf-8")) + len(
        report.model_dump_json().encode("utf-8")
    )


def _store_put(assessment_id: str, entry: tuple[AssessmentInput, AssessmentReport]) -> None:
    global _STORE_TOTAL_BYTES
    size = _entry_size(entry)
    with _STORE_GUARD:
        _STORE_TOTAL_BYTES -= _STORE_ENTRY_BYTES.pop(assessment_id, 0)
        _STORE[assessment_id] = entry
        _STORE_ENTRY_BYTES[assessment_id] = size
        _STORE_TOTAL_BYTES += size
        while _STORE and (
            len(_STORE) > _MAX_STORE_ENTRIES or _STORE_TOTAL_BYTES > _MAX_STORE_BYTES
        ):
            oldest = next(iter(_STORE))  # evict oldest (dict preserves insertion order)
            _STORE.pop(oldest)
            _STORE_TOTAL_BYTES -= _STORE_ENTRY_BYTES.pop(oldest, 0)


def _answer_cache_put(key: tuple[object, ...], assessment_id: str) -> None:
    with _ANSWER_CACHE_GUARD:
        _ANSWER_CACHE[key] = assessment_id
        while len(_ANSWER_CACHE) > _MAX_ANSWER_CACHE_ENTRIES:
            _ANSWER_CACHE.pop(next(iter(_ANSWER_CACHE)))


# Codex cross-review finding #6 (round 4, 2026-09-12), reproduced exactly as
# reported: two threads submitting the SAME patch against the SAME parent,
# synchronized so both miss the cache before either writes to it, each ran a
# full re-assessment and produced two distinct child assessments - the cache
# above only dedupes SEQUENTIAL repeats. A lock per cache key serializes the
# "check cache, else run and store" critical section (double-checked: the
# second thread through re-checks the cache once it has the lock, so it gets
# the first thread's result instead of also recomputing). Bounded the same
# FIFO way as the caches it guards.
#
# Codex#12 (round 8, 2026-09-12), reproduced exactly as reported: with
# capacity 1, obtaining lock A, requesting lock B (evicting A's dict
# entry - not the lock object itself, which the first caller still
# holds), then requesting "A" again returned a DIFFERENT, freshly
# created Lock object - uncontended, even while the original A is still
# held. Two concurrent callers for the SAME key could then both enter
# the "check cache, else recompute" critical section this is meant to
# serialize, silently defeating round 4's fix. A plain FIFO eviction can
# never be correct here: the whole point is to keep serving the SAME
# lock object to every caller for a key for as long as ANYONE might
# still be holding or waiting on it. Reference-counting each entry (an
# in-flight caller, not just a cache slot) and only ever removing an
# entry once its refcount reaches zero - never one still in use - is
# what actually preserves the singleflight guarantee under eviction.
_MAX_ANSWER_LOCKS = 5000
_ANSWER_LOCKS_GUARD = threading.Lock()


class _RefCountedLock:
    __slots__ = ("lock", "refcount")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.refcount = 0


_ANSWER_LOCKS: dict[tuple[object, ...], _RefCountedLock] = {}


def _evict_unused_answer_locks_locked() -> None:
    """Caller must already hold `_ANSWER_LOCKS_GUARD`. Evicts oldest
    entries (FIFO, like the other caches here) but only ones nobody is
    currently holding or waiting on - an in-use entry is never evicted,
    even if that means staying above `_MAX_ANSWER_LOCKS` until it frees
    up (this is a cheap secondary bound, not a hard memory limit; the
    per-key correctness guarantee above takes priority)."""
    if len(_ANSWER_LOCKS) <= _MAX_ANSWER_LOCKS:
        return
    for key, entry in list(_ANSWER_LOCKS.items()):
        if len(_ANSWER_LOCKS) <= _MAX_ANSWER_LOCKS:
            return
        if entry.refcount == 0:
            del _ANSWER_LOCKS[key]


@contextlib.contextmanager
def _answer_lock_for(key: tuple[object, ...]) -> Iterator[None]:
    with _ANSWER_LOCKS_GUARD:
        entry = _ANSWER_LOCKS.get(key)
        if entry is None:
            entry = _RefCountedLock()
            _ANSWER_LOCKS[key] = entry
            _evict_unused_answer_locks_locked()
        entry.refcount += 1
    entry.lock.acquire()
    try:
        yield
    finally:
        entry.lock.release()
        with _ANSWER_LOCKS_GUARD:
            entry.refcount -= 1
            if entry.refcount == 0 and _ANSWER_LOCKS.get(key) is entry:
                del _ANSWER_LOCKS[key]


# Codex cross-review finding #11 (2026-09-11): /v1/knowledge/reindex accepted
# requests regardless of Host/Origin - a form-encoded POST from any page could
# trigger it. The service is documented as loopback/localhost-only (spec
# Section 18); this makes that assumption an enforced check, not just a
# deployment note, without requiring authentication for the MVP. "testserver"
# is Starlette TestClient's own fixed default Host header, not a real,
# externally-routable hostname - allowing it only enables this app's own test
# suite, it grants nothing to an actual remote client.
_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "testserver"}


def _hostname_only(value: str) -> str:
    """Strip a port (and IPv6 brackets) from a Host/Origin/Referer authority."""
    value = value.strip()
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    head, sep, tail = value.rpartition(":")
    return head if sep and tail.isdigit() else value


def _effective_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    return 443 if scheme == "https" else 80


def _is_local_origin(request: Request) -> bool:
    """ADV-09 / Codex#3 (round 2, 2026-09-11): the original check inspected
    only the Host header. Host names the DESTINATION the client is connecting
    to - for a request routed to this loopback service, Host is always
    "localhost"/"127.0.0.1" regardless of who initiated it. Origin (or,
    failing that, Referer) names the PAGE that initiated the request, which is
    what actually distinguishes "this app called itself" from "a page on
    https://attacker.example made a cross-origin POST that happened to land
    here" - the real CSRF vector. Only a client that sends neither header
    (curl, httpx, this app's own scripts - never a browser navigation/fetch
    doing a real cross-origin request) falls back to the Host check.

    Codex#3 (round 8, 2026-09-12), reproduced exactly as reported:
    comparing only the HOSTNAME discarded scheme and port, so
    `Origin: http://localhost:9999` passed against a service actually
    running on `http://localhost:8000` - `_hostname_only` reduces both to
    "localhost". A hostile page on ANY other localhost port (a common
    situation: several dev servers bound to loopback at once) could
    therefore trigger this service. The browser's own same-origin policy
    already treats a different port as a different origin; this check must
    match that and compare the full (scheme, hostname, effective port)
    tuple against the ACTUAL port this request arrived on
    (`request.url`), not just a static hostname allowlist.
    """
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if value:
            # Codex#9 (round 12, 2026-09-13), reproduced exactly as
            # reported: `urlsplit(value).hostname`/`.port` raise a raw
            # ValueError for a malformed authority (an invalid IPv6
            # literal, or a non-numeric port) - direct calls with
            # `Origin: http://localhost:bad` or `http://[:::]:80`
            # propagated that ValueError straight out of this function,
            # becoming a generic 500 instead of the 403 every OTHER
            # untrusted-origin shape already gets from the caller below. A
            # header this malformed is exactly as untrusted as one naming
            # a different host outright - fail closed the same way.
            try:
                parts = urlsplit(value)
                hostname = (parts.hostname or "").lower()
                port = parts.port
            except ValueError:
                return False
            if hostname not in _ALLOWED_HOSTS:
                return False
            return parts.scheme == request.url.scheme and _effective_port(
                parts.scheme, port
            ) == _effective_port(request.url.scheme, request.url.port)
    host = _hostname_only(request.headers.get("host") or "")
    return host in _ALLOWED_HOSTS


def _peer_is_loopback(request: Request) -> bool:
    """Codex#1 (round 5, 2026-09-12): `Host`/`Origin`/`Referer` are values
    the CLIENT supplies in the request - they say nothing about who actually
    opened the TCP connection. If Uvicorn is ever bound to a non-loopback
    address (`--host 0.0.0.0`), a remote client can send `Host: localhost`
    (with no Origin/Referer) and pass `_is_local_origin` outright. The ASGI
    transport's peer address is the one thing a client cannot forge, so it is
    checked in addition to (not instead of) `_is_local_origin`: the peer
    check stops a remote client regardless of headers, and `_is_local_origin`
    still stops a same-machine browser page from CSRFing this service via a
    cross-origin request that arrives from the real loopback peer."""
    client = request.client
    if client is None:
        return False
    try:
        return ipaddress.ip_address(client.host).is_loopback
    except ValueError:
        return False


# Codex#5 / Antigravity SKOS-ADV-13 (round 4, 2026-09-12): only
# /v1/knowledge/reindex called _require_local_origin() (as it then was) - the
# assessment endpoints (create/get/answers/history/report), which can trigger
# LLM-provider spend and return excerpts of internal/confidential Knowledge
# Units, had no Host/Origin check at all. A DNS-rebinding attacker (a domain
# with a low-TTL record that rebinds to 127.0.0.1) or a same-machine page
# could hit them directly. This is a single choke point in front of every
# route (except /health, which returns nothing sensitive and takes no
# provider action) rather than a per-endpoint call that is easy to forget to
# add to the next new route.
@app.middleware("http")
async def _local_origin_gate(request: Request, call_next):  # type: ignore[no-untyped-def]
    if request.url.path != "/health" and not (
        _peer_is_loopback(request) and _is_local_origin(request)
    ):
        return JSONResponse(
            {"detail": "this endpoint only serves local clients"}, status_code=403
        )
    return await call_next(request)


def _settings() -> Settings:
    return Settings.from_env()


@dataclass
class _EvaluationResources:
    """Everything build_report() reads to produce an AssessmentReport,
    loaded exactly once - see _load_resources(). Codex#5 (round 10,
    2026-09-13): sharing one loaded instance between fingerprinting and
    evaluation (rather than each doing its own independent load) is what
    closes the race described on _evaluation_fingerprint() below."""

    catalogue: RuleCatalogue
    safe_tests: dict[str, SafeTest]
    conn: sqlite3.Connection | None


def _load_resources(settings: Settings) -> _EvaluationResources:
    catalogue = load_rules(settings.rules_root)
    safe_tests = load_safe_test_templates(settings.safe_tests_root)
    db_path = Path(settings.db_path)
    conn = connect(db_path, read_only=True) if db_path.exists() else None
    return _EvaluationResources(catalogue, safe_tests, conn)


def _build_report(
    inp: AssessmentInput, settings: Settings, resources: _EvaluationResources
) -> AssessmentReport:
    client = get_client(settings)
    return build_report(
        inp,
        resources.catalogue,
        settings=settings,
        client=client,
        index_conn=resources.conn,
        safe_tests=resources.safe_tests,
    )


@contextlib.contextmanager
def _admitted_resources(settings: Settings) -> Iterator[_EvaluationResources]:
    """Acquire _ASSESSMENT_SEMAPHORE (429 if already at capacity), THEN
    call _load_resources() (a real rule-load, safe-test-load, and sqlite
    connect()) - in that order, so a burst of requests beyond the
    concurrency cap is rejected immediately instead of each still paying
    the load cost first (self-review, round 10, 2026-09-13, restoring the
    round-9 Codex#6 fix's own stated intent - its comment on
    _ASSESSMENT_SEMAPHORE names "a real rule-load" as one of the two costs
    being bounded, not just the provider call).

    Codex#5 (round 11, 2026-09-13), reproduced exactly as reported:
    submit_answers() used to call _load_resources() BEFORE ever checking
    the semaphore - it has no choice but to load resources to compute the
    cache key and know whether a request is even a cache miss, but that
    is an argument for gating the load too (a cache hit paying the
    admission cost is preferable to snapshot/database work being
    unbounded), not for skipping the gate. Both call paths now go through
    this single admission+load helper, closing resources.conn and
    releasing the semaphore on the way out either way.
    """
    if not _ASSESSMENT_SEMAPHORE.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail=f"too many assessments in flight (max {_MAX_CONCURRENT_ASSESSMENTS}); "
            "retry shortly",
        )
    try:
        resources = _load_resources(settings)
        try:
            yield resources
        finally:
            if resources.conn is not None:
                resources.conn.close()
    finally:
        _ASSESSMENT_SEMAPHORE.release()


def _run(inp: AssessmentInput, settings: Settings) -> AssessmentReport:
    with _admitted_resources(settings) as resources:
        return _build_report(inp, settings, resources)


def _rules_and_safe_tests_fingerprint(resources: _EvaluationResources) -> str:
    """Codex#5 (round 9, 2026-09-12): a content digest over every rule/
    safe-test, so an edit to either catalogue is detectable, not just a
    path change.

    Codex#4 (round 11, 2026-09-13), reproduced exactly as reported: round
    10's fix made this "immediately adjacent" to _load_resources()'s own
    parse of the same files, closing the huge (semaphore-wait/LLM-call
    duration) window - but "immediately adjacent" is still a SEPARATE,
    non-atomic re-read of the live directories, and a rules edit landing
    in that much narrower window still meant the assessment evaluated
    parsed state A while the cache recorded fingerprint B (or vice versa).
    Hashing the canonical `model_dump_json()` of the exact `resources`
    already loaded - not a second read of anything - makes this provably
    atomic with what _evaluate() below will use: there is no read left to
    race against."""
    digest = hashlib.sha256()
    for rule in sorted(resources.catalogue.rules, key=lambda r: r.id):
        digest.update(rule.model_dump_json().encode("utf-8"))
        digest.update(b"\x1e")
    for key in sorted(resources.safe_tests):
        digest.update(key.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(resources.safe_tests[key].model_dump_json().encode("utf-8"))
        digest.update(b"\x1e")
    return digest.hexdigest()


def _evaluation_fingerprint(
    settings: Settings, resources: _EvaluationResources
) -> tuple[object, ...]:
    """Codex#5 (round 10, 2026-09-13), reproduced exactly as reported: this
    used to be computed from a SEPARATE, fresh read of rules_root/
    safe_tests_root and a SEPARATE connect() to the index, taken in
    submit_answers() BEFORE _run() loaded its own (also fresh) copies of
    the exact same resources to actually evaluate against - an arbitrary
    amount of time (a semaphore wait, a per-cache-key lock wait, the LLM
    call itself) could pass between those two independent reads. A rules
    edit or a reindex landing in that window meant the assessment actually
    ran against state B while the cache recorded fingerprint A; if the
    state later reverted to A, a later request could be served B's result
    under A's key.

    Taking the `resources` _load_resources() already loaded - the SAME
    object _evaluate() below is given, with no second, later read of
    rules_root/safe_tests_root/the index happening after this point -
    closes that window: the knowledge revision is read from the exact
    connection _evaluate() will query, not a second, independently-opened
    one that could see a different on-disk state after a concurrent
    os.replace() (an already-open read-only connection keeps its file
    descriptor on the original inode across an atomic rename elsewhere, so
    this is not just "read it a little sooner" - it is reading the state
    that will actually be queried, guaranteed). See
    _rules_and_safe_tests_fingerprint()'s own comment (round 11, Codex#4)
    for why the rule/safe-test content digest is now computed from
    `resources` too, rather than a second (even if immediately adjacent)
    read of the live directories.

    Codex#8 (round 10, 2026-09-13), reproduced exactly as reported: a
    corrupt or foreign SQLite file (one that opens fine but lacks this
    app's tables - e.g. `sqlite3.OperationalError: no such table: meta`)
    made this query raise straight out of submit_answers(), an untyped
    500, before the normal fail-closed assessment path ever got a chance
    to run. `_evaluate()` below already handles this safely -
    `verify_chunk_hashes()` (app/storage/integrity.py) treats a missing/
    malformed `meta`/`chunks` table as a POLICY_BLOCKED decision, not an
    exception - so swallowing the same class of error HERE and falling
    back to a plain `None` revision (an uninformative but valid cache-key
    component) defers entirely to that already-fail-closed path instead of
    duplicating its error handling.
    """
    revision: str | None = None
    if resources.conn is not None:
        try:
            revision = ChunkRepository(resources.conn).knowledge_revision()
        except sqlite3.Error:
            revision = None
    return (
        settings.mode.value,
        settings.allow_confidential,
        settings.llm_provider.value,
        settings.llm_model,
        settings.top_k,
        revision,
        _rules_and_safe_tests_fingerprint(resources),
    )


def _respond(report: AssessmentReport) -> AssessmentReport:
    if report.status is ReportStatus.POLICY_BLOCKED:
        raise HTTPException(status_code=422, detail=report.model_dump(mode="json"))
    return report


# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/assessments", response_model=AssessmentReport)
def create_assessment(inp: AssessmentInput) -> AssessmentReport:
    settings = _settings()
    report = _run(inp, settings)
    if report.result is not None:
        _store_put(report.result.assessment_id, (inp, report))
    return _respond(report)


@app.get("/v1/assessments/{assessment_id}", response_model=AssessmentReport)
def get_assessment(assessment_id: str) -> AssessmentReport:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return entry[1]


@app.post("/v1/assessments/{assessment_id}/answers", response_model=AssessmentReport)
def submit_answers(assessment_id: str, patch: AnswerPatch) -> AssessmentReport:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    if patch.is_empty():
        raise HTTPException(status_code=422, detail="the answer patch is empty")

    original_input, original_report = entry
    if (
        original_report.result is not None
        and original_report.result.revision >= _MAX_ANSWER_CHAIN_DEPTH
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                f"this assessment has reached the maximum answer-chain depth "
                f"({_MAX_ANSWER_CHAIN_DEPTH}); start a new assessment instead of "
                "continuing to patch this one"
            ),
        )
    try:
        new_input = apply_patch(original_input, patch)
    except AnswerValidationError as exc:
        raise HTTPException(status_code=422, detail={"rejected": exc.reasons}) from exc

    # Codex cross-review finding #10 (2026-09-11): patch.is_empty() only catches
    # "no field set at all" (every field None); a patch that sets a field to a
    # value that merges to a no-op (e.g. human_approval={}, which .update()s
    # into the existing dict and changes nothing) passed is_empty() and still
    # triggered a full re-assessment + a new stored revision every single call
    # - a free, repeatable cost/storage-growth amplifier. Comparing the merged
    # input to the original catches every such no-op, not just the empty case.
    if new_input == original_input:
        return _respond(original_report)

    # Codex cross-review finding #6, part 2 (round 2, 2026-09-11): a repeat of
    # the SAME (non-no-op) patch against the SAME parent - e.g. a client
    # retrying after a dropped response - used to re-run the full assessment
    # and create yet another store entry every time, even though the result
    # is byte-for-byte identical to one already computed. new_input's own
    # canonical JSON is deterministic (pydantic v2 preserves field-declaration
    # order), so it doubles as the dedup key.
    # Codex cross-review finding #3, part 2 (round 3, 2026-09-12): using that
    # JSON string itself as the dict key meant _ANSWER_CACHE retained a full
    # copy of every distinct merged input it had ever seen (bounded in COUNT
    # by _MAX_ANSWER_CACHE_ENTRIES, not in per-entry size). Hashing it first
    # gives a fixed-size key with the same dedup property.
    settings = _settings()
    # Codex#5 (round 9, 2026-09-12), reproduced exactly as reported: the key
    # below used to be only (assessment_id, merged-input hash) - it omitted
    # everything else build_report() actually depends on (rule/safe-test
    # content, the knowledge index revision, mode, provider/model), so a
    # cache hit could return a result computed against rules/knowledge that
    # have since changed. _evaluation_fingerprint() covers those inputs too.
    #
    # Codex#5 (round 10, 2026-09-13): resources are loaded exactly ONCE and
    # the SAME loaded catalogue/safe_tests/connection are reused for both
    # the fingerprint below and the actual evaluation on a cache miss - see
    # _evaluation_fingerprint()'s own comment for why the old
    # two-independent-reads approach was racy.
    #
    # Codex#5 (round 11, 2026-09-13), reproduced exactly as reported: that
    # load used to happen OUTSIDE any admission control - a burst of
    # requests could each still snapshot the rule/safe-test catalogues and
    # open the database, unbounded, before any of them reached a semaphore
    # check. _admitted_resources() gates the load itself, not just the
    # eventual build_report() call on a cache miss.
    with _admitted_resources(settings) as resources:
        cache_key = (
            assessment_id,
            hashlib.sha256(new_input.model_dump_json().encode("utf-8")).hexdigest(),
            *_evaluation_fingerprint(settings, resources),
        )

        # Codex cross-review finding #6 (round 4, 2026-09-12): the cache lookup
        # and the run-and-store below used to have no synchronization between
        # them, so two concurrent requests for the same (assessment_id,
        # new_input) could both miss the cache and both re-run the assessment.
        # A lock per cache key serializes this section; the second thread to
        # acquire it re-checks the cache (now populated by the first) before
        # deciding to run anything itself.
        with _answer_lock_for(cache_key):
            cached_id = _ANSWER_CACHE.get(cache_key)
            if cached_id is not None:
                cached_entry = _STORE.get(cached_id)
                if cached_entry is not None:
                    return _respond(cached_entry[1])

            report = _build_report(new_input, settings, resources)
            if report.result is not None:
                prev_revision = (
                    original_report.result.revision if original_report.result is not None else 1
                )
                report.result.supersedes = assessment_id
                report.result.revision = prev_revision + 1
                _store_put(report.result.assessment_id, (new_input, report))
                _answer_cache_put(cache_key, report.result.assessment_id)
    return _respond(report)


@app.get("/v1/assessments/{assessment_id}/history")
def get_history(assessment_id: str) -> list[dict[str, Any]]:
    """The revision chain, oldest first, reached by following ``supersedes``."""
    chain: list[dict[str, Any]] = []
    current: str | None = assessment_id
    seen: set[str] = set()
    while current is not None and current not in seen:
        seen.add(current)
        entry = _STORE.get(current)
        if entry is None or entry[1].result is None:
            break
        r = entry[1].result
        chain.append(
            {
                "assessment_id": r.assessment_id,
                "revision": r.revision,
                "supersedes": r.supersedes,
                "overall_status": r.overall_status.value,
            }
        )
        current = r.supersedes
    return list(reversed(chain))


@app.get("/v1/assessments/{assessment_id}/report")
def get_assessment_report(assessment_id: str) -> Response:
    entry = _STORE.get(assessment_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return Response(content=render_text(entry[1]), media_type="text/plain")


class KnowledgeDoc(BaseModel):
    # Codex cross-review finding #15 (2026-09-11): every other externally-fed
    # request model (AssessmentInput, AnswerPatch, ...) is extra="forbid";
    # this one silently discarded unknown fields instead of rejecting them.
    model_config = ConfigDict(extra="forbid")

    # Codex cross-review finding #2 (round 3, 2026-09-12): unbounded - the
    # real DoS vector was the YAML parser (fixed with a merge-key ban and its
    # own size cap in app/ingestion/parser.py), but bounding the whole
    # request body too is a cheap, independent second layer. Real Knowledge
    # Unit files are a few KB; this leaves generous headroom.
    content: str = Field(max_length=200_000)
    # Codex cross-review finding #4, part 2 (round 4, 2026-09-12), reproduced
    # exactly as reported: `source` is echoed back verbatim in EVERY returned
    # validation issue (see validate_knowledge_doc() below), so an unbounded
    # `source` turns one request into a response amplified by the number of
    # issues found - a one-million-character `source` produced a ~12 MB
    # response from a tiny request.
    source: str = Field(default="<api>", max_length=500)


@app.post("/v1/knowledge/validate")
def validate_knowledge_doc(doc: KnowledgeDoc) -> dict[str, Any]:
    """Read-only: validate one Knowledge Unit. Nothing is stored or written."""
    issues = validate_markdown(doc.content, source=doc.source)
    return {
        "errors": [i.__dict__ | {"level": i.level.value} for i in issues if i.level is Level.ERROR],
        "warnings": [
            i.__dict__ | {"level": i.level.value} for i in issues if i.level is Level.WARNING
        ],
        "valid": not any(i.level is Level.ERROR for i in issues),
    }


@app.post("/v1/knowledge/reindex", response_model=ReindexReport)
def reindex() -> ReindexReport:
    """Re-derive the FTS index from the existing verified read-only knowledge root.

    This does not accept or change knowledge content. classification + integrity
    are verified before the atomic swap; on failure the existing index is kept.
    The Host/Origin check is now the global `_local_origin_gate` middleware
    (round 4, 2026-09-12), not a per-endpoint call - see its definition."""
    # Codex#6 (round 10, 2026-09-13): see _REINDEX_LOCK's own comment - reject
    # immediately instead of blocking a worker thread on reindex_atomic()'s
    # own flock() while a rebuild is already running.
    #
    # Codex#2 (round 13, 2026-09-13), reproduced exactly as reported:
    # _REINDEX_LOCK only serializes callers within THIS process - with
    # multiple Uvicorn API workers, a concurrent request reaching a
    # DIFFERENT worker process passes this check too, and the flock inside
    # reindex_atomic() used to always BLOCK that worker's thread instead
    # of returning 429, then still perform a full, redundant rebuild once
    # admitted. blocking=False makes that flock attempt non-blocking; a
    # busy lock is reported back as decision.subject == "reindex-busy"
    # (see reindex_atomic()'s own docstring), checked below.
    if not _REINDEX_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=429, detail="a reindex is already running; retry shortly"
        )
    try:
        settings = _settings()
        report = reindex_atomic(settings.knowledge_root, settings.db_path, blocking=False)
    finally:
        _REINDEX_LOCK.release()
    if report.decision.subject == "reindex-busy":
        raise HTTPException(
            status_code=429, detail="a reindex is already running; retry shortly"
        )
    if not report.ok:
        # Codex#11 (round 9, 2026-09-12), reproduced exactly as reported:
        # `decision.reasons` can embed configured filesystem paths and raw
        # OS diagnostics (e.g. "knowledge root does not exist: /home/...")
        # - returning them verbatim in a public HTTP response discloses
        # server configuration to any local caller reaching this
        # unauthenticated, localhost-only endpoint. The full detail is
        # still logged server-side; the public response gets a stable,
        # generic reason instead.
        _logger.warning("reindex failed: %s", report.model_dump(mode="json"))
        redacted = report.model_copy(
            update={
                "decision": report.decision.model_copy(
                    update={"reasons": ["reindex failed; see server logs for details"]}
                )
            }
        )
        raise HTTPException(status_code=422, detail=redacted.model_dump(mode="json"))
    return report
