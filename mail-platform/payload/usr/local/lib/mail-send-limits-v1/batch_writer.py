"""One database-owning thread; one completion event per request, bounded queue."""
from collections import Counter
import queue
import threading
import time

class Ticket:

    def __init__(self, args, seconds):
        self.args = args
        self.created = time.monotonic()
        self.deadline = self.created + seconds
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.state = 'pending'
        self.result = None

    def expire(self):
        with self.lock:
            if self.state != 'pending':
                return False
            self.state = 'expired'
            self.result = ValueError('writer_queue_expired')
            self.done.set()
            return True

    def start(self):
        with self.lock:
            if self.state != 'pending':
                return 'ignored'
            if time.monotonic() >= self.deadline:
                self.state = 'expired'
                self.result = ValueError('writer_queue_expired')
                self.done.set()
                return 'expired'
            self.state = 'running'
            return 'running'

    def finish(self, result):
        with self.lock:
            if self.state in ('done', 'expired'):
                return False
            self.state = 'done'
            self.result = result
            self.done.set()
            return True

class BatchWriter:

    def __init__(self, factory, capacity=32, wait_seconds=1.0, batch_size=16, gather_seconds=0.002, on_failure=None):
        if not (type(capacity) is int and type(batch_size) is int and (1 <= batch_size <= 16 <= capacity <= 32) and (0 < wait_seconds <= 2) and (0 <= gather_seconds <= 0.01)):
            raise ValueError('batch_writer_bounds')
        self.factory = factory
        self.capacity = capacity
        self.wait_seconds = wait_seconds
        self.batch_size = batch_size
        self.gather_seconds = gather_seconds
        self.on_failure = on_failure
        self.queue = queue.Queue(capacity)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.closed = False
        self.poisoned = False
        self.start_error = None
        self.inflight = 0
        self.active = 0
        self.stats = Counter(started=0, finished=0, queue_full=0, queue_expired=0, unavailable=0, maximum_pending=0, wait_total_ms=0.0, wait_maximum_ms=0.0, batches=0, targeted_notifications=0, maximum_batch=0, gather_total_ms=0.0, gather_maximum_ms=0.0)
        self.thread = threading.Thread(target=self.run, name='admission-writer', daemon=False)
        self.thread.start()
        if not self.ready.wait(5):
            self.stop.set()
            raise ValueError('writer_start_timeout')
        if self.start_error is not None:
            self.thread.join(5)
            raise self.start_error

    def expired(self, ticket):
        if ticket.expire():
            with self.lock:
                self.stats['queue_expired'] += 1
                self.stats['targeted_notifications'] += 1

    def admit(self, *args):
        with self.lock:
            if self.closed or self.poisoned:
                self.stats['unavailable'] += 1
                raise ValueError('writer_unavailable')
            if self.inflight >= self.capacity:
                self.stats['queue_full'] += 1
                raise ValueError('writer_queue_full')
            ticket = Ticket(args, self.wait_seconds)
            try:
                self.queue.put_nowait(ticket)
            except queue.Full:
                self.stats['queue_full'] += 1
                raise ValueError('writer_queue_full')
            self.inflight += 1
            self.stats['maximum_pending'] = max(self.stats['maximum_pending'], self.queue.qsize())
        try:
            if not ticket.done.wait(max(0, ticket.deadline - time.monotonic())):
                self.expired(ticket)
                ticket.done.wait()
            if isinstance(ticket.result, BaseException):
                raise ticket.result
            return ticket.result
        finally:
            with self.lock:
                self.inflight -= 1

    def process(self, ledger, tickets):
        active = []
        for ticket in tickets:
            state = ticket.start()
            if state == 'expired':
                with self.lock:
                    self.stats['queue_expired'] += 1
                    self.stats['targeted_notifications'] += 1
            if state == 'running':
                active.append(ticket)
                wait = (time.monotonic() - ticket.created) * 1000
                with self.lock:
                    self.stats['started'] += 1
                    self.stats['wait_total_ms'] += wait
                    self.stats['wait_maximum_ms'] = max(self.stats['wait_maximum_ms'], wait)
        if not active:
            return
        with self.lock:
            self.active = len(active)
            self.stats['batches'] += 1
            self.stats['maximum_batch'] = max(self.stats['maximum_batch'], len(active))
        try:
            results = ledger.admit_many([ticket.args for ticket in active])
            if len(results) != len(active):
                raise ValueError('batch_result_count')
        except BaseException as error:
            self.record_failure(error)
            results = [ValueError('batch_storage_failure') for _ in active]
            try:
                unsafe = ledger.db.in_transaction
            except Exception:
                unsafe = True
            if unsafe or not isinstance(error, Exception):
                with self.lock:
                    self.poisoned = True
        for ticket, result in zip(active, results):
            ticket.finish(result)
        with self.lock:
            self.stats['finished'] += len(active)
            self.stats['targeted_notifications'] += len(active)
            self.active = 0

    def run(self):
        tickets = []
        try:
            with self.factory() as ledger:
                self.ready.set()
                while not self.stop.is_set() or not self.queue.empty():
                    try:
                        ticket = self.queue.get(timeout=0.05)
                    except queue.Empty:
                        continue
                    tickets = [ticket]
                    gather_started = time.monotonic()
                    deadline = gather_started + self.gather_seconds
                    while len(tickets) < self.batch_size:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        try:
                            tickets.append(self.queue.get(timeout=remaining))
                        except queue.Empty:
                            break
                    gathering = (time.monotonic() - gather_started) * 1000
                    with self.lock:
                        self.stats['gather_total_ms'] += gathering
                        self.stats['gather_maximum_ms'] = max(self.stats['gather_maximum_ms'], gathering)
                        poisoned = self.poisoned
                    if poisoned:
                        for ticket in tickets:
                            self.refuse(ticket)
                    else:
                        self.process(ledger, tickets)
                    for _ in tickets:
                        self.queue.task_done()
                    tickets = []
        except BaseException as error:
            self.record_failure(error)
            self.start_error = ValueError('writer_thread_failed')
            with self.lock:
                self.poisoned = True
            self.ready.set()
            for ticket in tickets:
                self.refuse(ticket)
            with self.lock:
                self.active = 0
            while True:
                try:
                    ticket = self.queue.get_nowait()
                except queue.Empty:
                    break
                self.refuse(ticket)
                self.queue.task_done()

    def refuse(self, ticket):
        if ticket.finish(ValueError('writer_unavailable')):
            with self.lock:
                self.stats['unavailable'] += 1
                self.stats['targeted_notifications'] += 1

    def record_failure(self, error):
        with self.lock:
            self.last_failure = {'class': type(error).__name__, 'sqlite_code': getattr(error, 'sqlite_errorcode', None)}
        if self.on_failure is not None:
            try:
                self.on_failure(error)
            except Exception as save_error:
                with self.lock:
                    self.last_failure['save_error'] = type(save_error).__name__

    def snapshot(self):
        with self.lock:
            return dict(self.stats, pending=self.queue.qsize(), active=self.active, closed=self.closed, poisoned=self.poisoned, last_failure=getattr(self, 'last_failure', None))

    def close(self):
        with self.lock:
            self.closed = True
        self.stop.set()
        self.thread.join(5)
        if self.thread.is_alive():
            raise ValueError('writer_not_drained')
