#!/usr/bin/env python3
"""Ask several DNS resolvers about the same domains (stdlib, Python 3.7+)."""

import collections
import random
import selectors
import socket
import struct
import time

CODE_OK = "ok"
CODE_NXDOMAIN = "nxdomain"
CODE_NOANSWER = "noanswer"
CODE_SERVFAIL = "servfail"
CODE_REFUSED = "refused"
CODE_TIMEOUT = "timeout"
CODE_ERROR = "error"

_CODE_TOKEN = {
    CODE_NXDOMAIN: "NX",
    CODE_NOANSWER: "NA",
    CODE_SERVFAIL: "SF",
    CODE_REFUSED: "RF",
    CODE_TIMEOUT: "TO",
    CODE_ERROR: "ER",
}

_RCODE_CODE = {
    2: CODE_SERVFAIL,
    3: CODE_NXDOMAIN,
    5: CODE_REFUSED,
}

KIND_GLOBAL = "global"
KIND_RUSSIAN = "russian"
KIND_NSDI = "nsdi"

DNS_PORT = 53
_MAX_UDP = 4096
_DRAIN_LIMIT = 256
_CONFLICT_WINDOW = 5.0  # keep tx ids a bit after the answer, to catch duplicates
_MIN_TICK = 0.005
_MAX_TICK = 0.25
_SWEEP_INTERVAL = 2.0

_SEND_OK = "sent"
_SEND_AGAIN = "again"
_SEND_FAILED = "failed"

Resolver = collections.namedtuple("Resolver", "slug ip kind name family port")
Resolver.__new__.__defaults__ = (DNS_PORT,)

Outcome = collections.namedtuple("Outcome", "code ips attempts elapsed_ms conflict")

ProbeResult = collections.namedtuple(
    "ProbeResult",
    "by_domain resolvers dead elapsed domains queries_total queries_done "
    "conflicts unmatched stopped_early",
)

_rng = random.SystemRandom()


def _family_of(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return socket.AF_INET
    except (OSError, ValueError):
        pass
    if not getattr(socket, "has_ipv6", False):
        return None
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return socket.AF_INET6
    except (OSError, ValueError, AttributeError):
        return None


def normalize_ip(ip, family):
    try:
        return socket.inet_ntop(family, socket.inet_pton(family, ip))
    except (OSError, ValueError):
        return ip


def parse_resolver_line(line):
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    parts = [p.strip() for p in text.split(",")]
    if len(parts) < 3:
        return None
    slug, ip, kind = parts[0], parts[1], parts[2].lower()
    name = parts[3] if len(parts) > 3 and parts[3] else slug
    if not slug or not ip:
        return None
    if kind not in (KIND_GLOBAL, KIND_RUSSIAN, KIND_NSDI):
        kind = KIND_RUSSIAN
    family = _family_of(ip)
    if family is None:
        return None
    return Resolver(slug, normalize_ip(ip, family), kind, name, family, DNS_PORT)


def load_resolvers(path):
    try:
        fh = open(path, "r", encoding="utf-8")
    except (IOError, OSError):
        return []
    resolvers = []
    seen_slug = set()
    seen_ip = set()
    with fh:
        for raw in fh:
            res = parse_resolver_line(raw)
            if res is None:
                continue
            if res.slug in seen_slug or res.ip in seen_ip:
                continue
            seen_slug.add(res.slug)
            seen_ip.add(res.ip)
            resolvers.append(res)
    return resolvers


def encode_qname(domain):
    name = (domain or "").strip().rstrip(".").lower()
    if not name:
        raise ValueError("empty domain")
    out = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError("bad label")
        out += struct.pack("B", len(raw)) + raw
    out += b"\x00"
    if len(out) > 255:
        raise ValueError("name too long")
    return out


def udp_endpoint(res):
    # Windows wants a 4-tuple for IPv6
    if res.family == socket.AF_INET6:
        return (res.ip, res.port, 0, 0)
    return (res.ip, res.port)


def question_key(domain):
    return (domain or "").strip().rstrip(".").lower().encode("ascii", "ignore")


def build_query(qname, tx_id):
    header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", 1, 1)


def _read_qname(data, offset):
    labels = []
    total = 0
    while True:
        if offset >= len(data):
            return None, offset
        length = data[offset]
        if length == 0:
            return b".".join(labels).lower(), offset + 1
        if length & 0xC0:
            return None, offset
        offset += 1
        total += length + 1
        if total > 255 or offset + length > len(data):
            return None, offset
        labels.append(data[offset:offset + length])
        offset += length


def _skip_name(data, offset):
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _code_from_reply(rcode, ips):
    if rcode == 0:
        return CODE_OK if ips else CODE_NOANSWER
    return _RCODE_CODE.get(rcode, CODE_ERROR)


def _same_answer(outcome, code, ips):
    if outcome.code != code:
        return False
    if code != CODE_OK:
        return True
    return tuple(sorted(outcome.ips)) == tuple(sorted(ips))


def parse_response(data, expected_tx_id, expected_question):
    # None = not a reply to this query (wrong id, wrong name, garbage)
    if len(data) < 12:
        return None
    tx_id, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if tx_id != expected_tx_id:
        return None
    if not flags & 0x8000:
        return None
    rcode = flags & 0x000F

    offset = 12
    question_ok = qdcount == 0
    for index in range(qdcount):
        name, offset = _read_qname(data, offset)
        if name is None or offset + 4 > len(data):
            return None
        qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
        offset += 4
        if index == 0 and qtype == 1 and qclass == 1 and name == expected_question:
            question_ok = True
    if not question_ok:
        return None

    ips = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(
            ">HHIH", data[offset:offset + 10]
        )
        offset += 10
        if offset + rdlength > len(data):
            break
        if rtype == 1 and rdlength == 4:
            ips.append(".".join(str(b) for b in data[offset:offset + 4]))
        offset += rdlength
    return rcode, ips


class UdpTransport(object):

    def __init__(self):
        self._socks = {}
        self._selector = selectors.DefaultSelector()

    def open(self, family):
        if family in self._socks:
            return True
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            return False
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except (OSError, AttributeError):
                pass
        try:
            sock.setblocking(False)
            self._selector.register(sock, selectors.EVENT_READ, family)
        except (OSError, ValueError):
            try:
                sock.close()
            except OSError:
                pass
            return False
        self._socks[family] = sock
        return True

    def send(self, family, data, address):
        sock = self._socks.get(family)
        if sock is None:
            raise OSError("no socket for family {}".format(family))
        sock.sendto(data, address)

    def poll(self, timeout):
        if not self._socks:
            time.sleep(min(timeout, _MAX_TICK))
            return []
        try:
            events = self._selector.select(timeout)
        except (OSError, ValueError):
            return []
        received = []
        for key, _mask in events:
            sock = key.fileobj
            family = key.data
            for _ in range(_DRAIN_LIMIT):
                try:
                    data, address = sock.recvfrom(_MAX_UDP)
                except (BlockingIOError, InterruptedError):
                    break
                except ConnectionResetError:
                    # Windows: ICMP from a closed port shows up on the next recv
                    continue
                except OSError:
                    break
                received.append((family, data, address))
        return received

    def close(self):
        try:
            self._selector.close()
        except (OSError, ValueError):
            pass
        for sock in self._socks.values():
            try:
                sock.close()
            except OSError:
                pass
        self._socks = {}


class _Pending(object):
    __slots__ = ("domain", "qname", "question", "res_index", "attempt",
                 "deadline", "started", "awaiting_send", "settled", "tx_ids")

    def __init__(self, domain, qname, question, res_index, started):
        self.domain = domain
        self.qname = qname
        self.question = question
        self.res_index = res_index
        self.attempt = 0
        self.deadline = 0.0
        self.started = started
        self.awaiting_send = True
        self.settled = False
        self.tx_ids = []


class _Prober(object):
    def __init__(self, domains, resolvers, timeout, attempts, qps_by_kind,
                 max_inflight, max_inflight_per_server, breaker_failures,
                 max_seconds, stop_event, progress, transport, clock):
        self.timeout = max(0.05, float(timeout))
        self.attempts = max(1, int(attempts))
        self.qps_by_kind = qps_by_kind
        self.max_inflight = max(1, int(max_inflight))
        self.per_server = max(1, int(max_inflight_per_server))
        self.breaker_failures = max(1, int(breaker_failures))
        self.max_seconds = float(max_seconds)
        self.stop_event = stop_event
        self.progress = progress
        self.clock = clock
        self.transport = transport

        self.resolvers = []
        self.domains = []
        self.by_domain = {}
        self.dead = []
        self.conflicts = 0
        self.unmatched = 0
        self.queries_done = 0
        self.stopped_early = False

        self._prepare(domains, resolvers)

    def _prepare(self, domains, resolvers):
        usable = []
        for res in resolvers:
            if self.transport.open(res.family):
                usable.append(res)
        self.resolvers = usable
        self.count = len(usable)
        self.by_ip = {}
        for index, res in enumerate(usable):
            self.by_ip[res.ip] = index

        seen = set()
        encoded = []
        for raw in domains:
            name = (raw or "").strip().rstrip(".").lower()
            if not name or name in seen:
                continue
            seen.add(name)
            try:
                qname = encode_qname(name)
            except (ValueError, UnicodeError):
                self.by_domain[name] = dict(
                    (r.slug, Outcome(CODE_ERROR, (), 0, 0.0, False))
                    for r in usable
                )
                self.queries_done += len(usable)
                continue
            encoded.append((name, qname, question_key(name)))
            self.by_domain.setdefault(name, {})
        self.domains = encoded

        size = self.count
        self.queue_pos = [0] * size
        self.retry_queue = [collections.deque() for _ in range(size)]
        self.tokens = [1.0] * size
        self.last_fill = [0.0] * size
        self.inflight_n = [0] * size
        self.consec_fail = [0] * size
        self.dead = [False] * size
        self.active = {}
        self.txmap = {}
        self.recent = {}
        self.conflicted = set()
        self._last_sweep = 0.0
        self.queries_total = len(self.domains) * size + self.queries_done

    def _qps(self, index):
        kind = self.resolvers[index].kind
        return max(0.1, float(self.qps_by_kind.get(kind, self.qps_by_kind.get(
            KIND_RUSSIAN, 10.0))))

    def run(self):
        start = self.clock()
        for index in range(self.count):
            self.last_fill[index] = start
        deadline = start + self.max_seconds
        last_report = start

        while True:
            now = self.clock()
            if self.stop_event is not None and self.stop_event.is_set():
                self.stopped_early = True
                break
            if now >= deadline:
                self.stopped_early = True
                break

            self._dispatch(now)
            if not self.active and self._queues_drained():
                break

            self._sweep_recent(now)
            wait = self._next_tick(now, deadline)
            for family, data, address in self.transport.poll(wait):
                self._handle(family, data, address, self.clock())
            self._expire(self.clock())

            if self.progress is not None:
                now = self.clock()
                if now - last_report >= 5.0:
                    last_report = now
                    self.progress(self.queries_done, self.queries_total)

        elapsed = self.clock() - start
        self._finalize()
        if self.progress is not None:
            self.progress(self.queries_done, self.queries_total)
        return ProbeResult(
            by_domain=self.by_domain,
            resolvers=self.resolvers,
            dead=tuple(
                self.resolvers[i].slug for i in range(self.count) if self.dead[i]
            ),
            elapsed=elapsed,
            domains=len(self.by_domain),
            queries_total=self.queries_total,
            queries_done=self.queries_done,
            conflicts=self.conflicts,
            unmatched=self.unmatched,
            stopped_early=self.stopped_early,
        )

    def _queues_drained(self):
        for index in range(self.count):
            if self.dead[index]:
                continue
            if self.retry_queue[index]:
                return False
            if self.queue_pos[index] < len(self.domains):
                return False
        return True

    def _refill(self, index, now):
        elapsed = now - self.last_fill[index]
        if elapsed <= 0:
            return
        self.last_fill[index] = now
        burst = max(1.0, self._qps(index) * 0.25)
        self.tokens[index] = min(burst, self.tokens[index] + elapsed * self._qps(index))

    def _total_inflight(self):
        return len(self.active)

    def _dispatch(self, now):
        for index in range(self.count):
            if self.dead[index]:
                continue
            self._refill(index, now)
            while self.tokens[index] >= 1.0:
                # retries already count as inflight, so send them even if the window is full
                if self.retry_queue[index]:
                    pending = self.retry_queue[index].popleft()
                    state = self._transmit(pending, now)
                    if state == _SEND_AGAIN:
                        self.retry_queue[index].appendleft(pending)
                        break
                    self.tokens[index] -= 1.0
                    continue
                if self.inflight_n[index] >= self.per_server:
                    break
                if self._total_inflight() >= self.max_inflight:
                    break
                if self.queue_pos[index] >= len(self.domains):
                    break
                name, qname, question = self.domains[self.queue_pos[index]]
                pending = _Pending(name, qname, question, index, now)
                self.active[(index, name)] = pending
                self.inflight_n[index] += 1
                state = self._transmit(pending, now)
                if state == _SEND_AGAIN:
                    del self.active[(index, name)]
                    self.inflight_n[index] -= 1
                    break
                self.queue_pos[index] += 1
                self.tokens[index] -= 1.0

    def _transmit(self, pending, now):
        index = pending.res_index
        res = self.resolvers[index]
        tx_id = self._new_tx_id(index)
        try:
            self.transport.send(
                res.family, build_query(pending.qname, tx_id), udp_endpoint(res)
            )
        except (BlockingIOError, InterruptedError):
            return _SEND_AGAIN
        except OSError:
            self._settle(pending, CODE_ERROR, (), now)
            self._register_failure(index)
            return _SEND_FAILED
        pending.attempt += 1
        pending.awaiting_send = False
        pending.deadline = now + self.timeout
        pending.tx_ids.append(tx_id)
        self.txmap[(index, tx_id)] = pending
        return _SEND_OK

    def _new_tx_id(self, index):
        for _ in range(16):
            tx_id = _rng.getrandbits(16)
            if (index, tx_id) not in self.txmap and (index, tx_id) not in self.recent:
                return tx_id
        return _rng.getrandbits(16)

    def _handle(self, family, data, address, now):
        index = self.by_ip.get(normalize_ip(address[0], family))
        if index is None or len(data) < 12:
            self.unmatched += 1
            return
        tx_id = struct.unpack(">H", data[:2])[0]
        key = (index, tx_id)
        pending = self.txmap.get(key)
        if pending is None:
            previous = self.recent.get(key)
            if previous is None:
                self.unmatched += 1
                return
            self._note_conflict(index, previous[0], data, tx_id)
            return
        parsed = parse_response(data, tx_id, pending.question)
        if parsed is None:
            self.unmatched += 1
            return
        rcode, ips = parsed
        code = _code_from_reply(rcode, ips)
        self.consec_fail[index] = 0
        self._settle(pending, code, tuple(ips), now)

    def _note_conflict(self, index, domain, data, tx_id):
        parsed = parse_response(data, tx_id, question_key(domain))
        if parsed is None:
            self.unmatched += 1
            return
        rcode, ips = parsed
        code = _code_from_reply(rcode, ips)
        slug = self.resolvers[index].slug
        first = self.by_domain.get(domain, {}).get(slug)
        if first is None or _same_answer(first, code, ips):
            return
        self.conflicted.add((index, domain))
        self.conflicts += 1

    def _expire(self, now):
        for pending in list(self.active.values()):
            if pending.awaiting_send or now < pending.deadline:
                continue
            index = pending.res_index
            if pending.attempt < self.attempts and not self.dead[index]:
                pending.awaiting_send = True
                self.retry_queue[index].append(pending)
                continue
            self._settle(pending, CODE_TIMEOUT, (), now)
            self._register_failure(index)

    def _settle(self, pending, code, ips, now):
        if pending.settled:
            return
        pending.settled = True
        index = pending.res_index
        slug = self.resolvers[index].slug
        elapsed_ms = max(0.0, (now - pending.started) * 1000.0)
        self.by_domain.setdefault(pending.domain, {})[slug] = Outcome(
            code, ips, pending.attempt, elapsed_ms, False
        )
        self.queries_done += 1
        if self.active.pop((index, pending.domain), None) is not None:
            self.inflight_n[index] -= 1
        self._retire_tx_ids(pending, now)

    def _retire_tx_ids(self, pending, now):
        index = pending.res_index
        expiry = now + _CONFLICT_WINDOW
        for tx_id in pending.tx_ids:
            self.txmap.pop((index, tx_id), None)
            self.recent[(index, tx_id)] = (pending.domain, expiry)
        pending.tx_ids = []

    def _sweep_recent(self, now):
        if now - self._last_sweep < _SWEEP_INTERVAL:
            return
        self._last_sweep = now
        for key in [k for k, v in self.recent.items() if v[1] <= now]:
            self.recent.pop(key, None)

    def _register_failure(self, index):
        self.consec_fail[index] += 1
        if self.dead[index] or self.consec_fail[index] < self.breaker_failures:
            return
        self.dead[index] = True
        self.queue_pos[index] = len(self.domains)
        now = self.clock()
        queued = list(self.retry_queue[index])
        self.retry_queue[index].clear()
        for pending in queued:
            self._settle(pending, CODE_TIMEOUT, (), now)

    def _next_tick(self, now, deadline):
        wait = min(_MAX_TICK, max(_MIN_TICK, deadline - now))
        for pending in self.active.values():
            if pending.awaiting_send:
                continue
            wait = min(wait, max(_MIN_TICK, pending.deadline - now))
        for index in range(self.count):
            if self.dead[index] or self.tokens[index] >= 1.0:
                continue
            if not self.retry_queue[index] and self.queue_pos[index] >= len(
                self.domains
            ):
                continue
            need = (1.0 - self.tokens[index]) / self._qps(index)
            wait = min(wait, max(_MIN_TICK, need))
        return wait

    def _finalize(self):
        now = self.clock()
        for pending in list(self.active.values()):
            self._settle(pending, CODE_TIMEOUT, (), now)
        for index, domain in self.conflicted:
            if index >= self.count:
                continue
            slug = self.resolvers[index].slug
            outcome = self.by_domain.get(domain, {}).get(slug)
            if outcome is not None:
                self.by_domain[domain][slug] = outcome._replace(conflict=True)


def probe(domains, resolvers, timeout=1.5, attempts=3, qps_by_kind=None,
          max_inflight=600, max_inflight_per_server=100, breaker_failures=15,
          max_seconds=300.0, stop_event=None, progress=None, transport=None,
          clock=None):
    if qps_by_kind is None:
        qps_by_kind = {KIND_GLOBAL: 40.0, KIND_RUSSIAN: 15.0, KIND_NSDI: 15.0}
    own_transport = transport is None
    transport = transport if transport is not None else UdpTransport()
    try:
        prober = _Prober(
            domains=domains,
            resolvers=resolvers,
            timeout=timeout,
            attempts=attempts,
            qps_by_kind=qps_by_kind,
            max_inflight=max_inflight,
            max_inflight_per_server=max_inflight_per_server,
            breaker_failures=breaker_failures,
            max_seconds=max_seconds,
            stop_event=stop_event,
            progress=progress,
            transport=transport,
            clock=clock or time.monotonic,
        )
        return prober.run()
    finally:
        if own_transport:
            transport.close()


COLUMNS = (
    "dns_probe_ok",
    "dns_probe_total",
    "dns_probe_nsdi",
    "dns_probe_detail",
    "dns_probe_variants",
)

META_COLUMNS = ("dns_probe_resolvers", "dns_probe_meta")

EMPTY_COLUMNS = dict((name, "") for name in COLUMNS)

META_VERSION = "1"


def _variant_letter(index):
    letters = ""
    index += 1
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return letters


def format_columns(outcomes, resolvers):
    if not outcomes:
        return dict(EMPTY_COLUMNS)

    order = []
    counts = {}
    first_seen = {}
    for position, res in enumerate(resolvers):
        outcome = outcomes.get(res.slug)
        if outcome is None or outcome.code != CODE_OK:
            continue
        key = tuple(sorted(outcome.ips))
        if key not in counts:
            counts[key] = 0
            first_seen[key] = position
            order.append(key)
        counts[key] += 1

    labelled = sorted(order, key=lambda k: (-counts[k], first_seen[k]))
    letters = dict((key, _variant_letter(i)) for i, key in enumerate(labelled))

    detail = []
    resolved = 0
    probed = 0
    nsdi_codes = []
    for res in resolvers:
        outcome = outcomes.get(res.slug)
        if outcome is None:
            continue
        probed += 1
        if outcome.code == CODE_OK:
            resolved += 1
            token = letters[tuple(sorted(outcome.ips))]
        else:
            token = _CODE_TOKEN.get(outcome.code, "ER")
        if outcome.conflict:
            token += "*"
        detail.append("{}={}".format(res.slug, token))
        if res.kind == KIND_NSDI:
            nsdi_codes.append(outcome.code)

    variants = "|".join(
        "{}={}".format(letters[key], ",".join(key)) for key in labelled if key
    )

    if not nsdi_codes:
        nsdi = ""
    elif all(code == CODE_OK for code in nsdi_codes):
        nsdi = CODE_OK
    else:
        nsdi = next(code for code in nsdi_codes if code != CODE_OK)

    return {
        "dns_probe_ok": str(resolved),
        "dns_probe_total": str(probed),
        "dns_probe_nsdi": nsdi,
        "dns_probe_detail": ";".join(detail),
        "dns_probe_variants": variants,
    }


def format_roster(resolvers):
    return ";".join(
        "{}={}/{}".format(r.slug, r.ip, r.kind) for r in resolvers
    )


def format_meta(result):
    fields = [
        ("v", META_VERSION),
        ("domains", str(result.domains)),
        ("queries", str(result.queries_done)),
        ("planned", str(result.queries_total)),
        ("elapsed", "{:.1f}".format(result.elapsed)),
        ("conflicts", str(result.conflicts)),
        ("unmatched", str(result.unmatched)),
        ("partial", "1" if result.stopped_early else "0"),
    ]
    if result.dead:
        fields.append(("dead", ",".join(result.dead)))
    return ";".join("{}={}".format(k, v) for k, v in fields)


def parse_roster(text):
    out = []
    for chunk in (text or "").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        slug, _, rest = chunk.partition("=")
        ip, _, kind = rest.partition("/")
        if not slug.strip() or not ip.strip():
            continue
        out.append(
            {"slug": slug.strip(), "ip": ip.strip(), "kind": kind.strip() or ""}
        )
    return out


def parse_meta(text):
    out = {}
    for chunk in (text or "").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        key = key.strip()
        if key:
            out[key] = value.strip()
    return out
