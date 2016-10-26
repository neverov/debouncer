from __future__ import print_function
import psycopg2
import urlparse
import json

from psycopg2.extras import RealDictCursor

import log

logger = log.build_logger(__name__)

@log.logfn(logger)
def connect(db_url):
    logger.info('connecting to: {}'.format(db_url))
    urlparse.uses_netloc.append("postgres")
    url = urlparse.urlparse(db_url)
    conn = psycopg2.connect(database=url.path[1:],
                            user=url.username,
                            password=url.password,
                            host=url.hostname,
                            port=url.port)
    logger.info('connected to database: {}'.format(db_url))
    return conn

@log.logfn(logger)
def migrate(conn):
    with conn, conn.cursor() as cur:
        return cur.execute("""CREATE TABLE IF NOT EXISTS users (
                                user_id text PRIMARY KEY,
                                credentials jsonb,
                                timer_enabled boolean,
                                delay integer,
                                messages integer,
                                checked_at timestamp
                              );""")

@log.logfn(logger)
def save_user(conn, user_id, credentials):
    with conn, conn.cursor() as cur:
        return cur.execute("""INSERT INTO users (user_id, credentials, timer_enabled, delay, messages)
                              VALUES (%s, %s, %s, %s, %s)
                              ON CONFLICT (user_id) DO UPDATE
                              SET credentials = %s""",
                              (user_id, json.dumps(credentials), False, 300, 0, json.dumps(credentials)))

@log.logfn(logger)
def save_delay(conn, user_id, delay):
    with conn, conn.cursor() as cur:
        return cur.execute("UPDATE users SET delay = %s WHERE user_id = %s", (delay, user_id,))

@log.logfn(logger)
def get_credentials(conn, user_id):
    with conn, conn.cursor() as cur:
        cur.execute("SELECT credentials FROM users WHERE user_id = %s;", (user_id,))
        res = cur.fetchone()
        return res[0] if res is not None else None

@log.logfn(logger)
def get_timers(conn):
    with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT user_id, timer_enabled, delay FROM users;")
        return cur.fetchall()

@log.logfn(logger)
def get_active_timers(conn):
    with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""SELECT user_id, messages
                       FROM users
                       WHERE timer_enabled = true AND
                             (COALESCE(NULLIF(checked_at ,'-infinity'::timestamp), '-infinity'::timestamp) + delay * interval '1 second') <= now();""")
        return cur.fetchall()

@log.logfn(logger)
def get_timer(conn, user_id):
    with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT user_id, timer_enabled, delay, messages FROM users WHERE user_id = %s;", (user_id,))
        return cur.fetchone()

@log.logfn(logger)
def save_timer(conn, user_id, enabled):
    with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("UPDATE users SET timer_enabled = %s WHERE user_id = %s", (enabled, user_id))

@log.logfn(logger)
def save_run(conn, user_id, messages):
    with conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        return cur.execute("UPDATE users SET (messages, checked_at) = (%s, now()) WHERE user_id = %s", (messages, user_id))