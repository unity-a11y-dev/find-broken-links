import os
import redis
from rq import Queue, SimpleWorker, Worker
from rq.timeouts import TimerDeathPenalty

listen = ['default']

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')

# Handle Heroku Redis SSL requirement
conn_kwargs = {}
if redis_url.startswith('rediss://'):
    conn_kwargs['ssl_cert_reqs'] = None

conn = redis.from_url(redis_url, **conn_kwargs)

if __name__ == '__main__':
    # Explicitly pass connection to Queues to ensure they use the correct Redis instance
    queues = [Queue(name, connection=conn) for name in listen]
    worker_cls = SimpleWorker if os.name == 'nt' else Worker
    worker = worker_cls(queues, connection=conn)
    if os.name == 'nt':
        # Windows has no SIGALRM; TimerDeathPenalty keeps per-job timeouts functional.
        worker.death_penalty_class = TimerDeathPenalty
    print(f"Worker listening on queues: {listen} with connection: {conn} ({worker_cls.__name__})")
    worker.work()
