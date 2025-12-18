import os
import redis
from rq import Worker, Queue

listen = ['default']

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')

# Handle Heroku Redis SSL requirement
conn_kwargs = {}
if redis_url.startswith('rediss://'):
    conn_kwargs['ssl_cert_reqs'] = None

conn = redis.from_url(redis_url, **conn_kwargs)

if __name__ == '__main__':
    worker = Worker(map(Queue, listen), connection=conn)
    worker.work()
