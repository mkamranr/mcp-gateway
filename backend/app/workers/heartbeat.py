"""Worker heartbeat registry shared by the worker, its container healthcheck and the status API."""

HEARTBEAT_KEY = "workers:heartbeat"  # zset: member = worker host name, score = unix time of its last beat
HEARTBEAT_FRESH_SECONDS = 60
