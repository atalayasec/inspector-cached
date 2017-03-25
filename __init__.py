#!/usr/bin/env python

import argparse
import logging

from app import app
from db import DB
from virustotal import Virustotal
from cuckoo import Cuckoo
from ssl_validator import SSLSite
from top_validator import TopSite
import analysis_manager
import scheduler

parser = argparse.ArgumentParser()
parser.add_argument('--host', type=str, default="localhost", help='bind host')
parser.add_argument('--port', type=str, default=8080, help='bind port')
parser.add_argument(
    '--debug', "-d", default=False, action="store_true", help='enable debug')
parser.add_argument(
    '--db-debug',
    "-D",
    default=False,
    action="store_true",
    help='enable database debugging')
parser.add_argument(
    '--cachebuster',
    "-c",
    default=False,
    action="store_true",
    help='enable cachebusting settings')
parser.add_argument(
    '--task-refresh',
    "-r",
    default=3600,
    type=int,
    help='analysis task upstream refresh period')
args = parser.parse_args()

host, port = args.host, args.port
debug = args.debug

app.config.update(
    dict(
        DEBUG=debug,
        CACHEBUSTER=args.cachebuster,
        DB_DEBUG=args.db_debug,
        TASK_REFRESH=args.task_refresh))

if app.config["CACHEBUSTER"]:
    from utils import cache_buster
    app.after_request(cache_buster)

db_obj = DB(app.config["DBUSER"],
            app.config["DBPASSWORD"],
            app.config["DBHOST"],
            app.config["DBPORT"],
            app.config["DBNAME"],
            debug=app.config["DEBUG"],
            db_debug=app.config["DB_DEBUG"])

v = Virustotal(app.config["VIRUSTOTAL_API_KEY"], debug=debug)

c = Cuckoo(
    app.config["CUCKOO_API_URL"],
    app.config["CUCKOO_API_USER"],
    app.config["CUCKOO_API_PASS"],
    debug=debug)

s = SSLSite(debug=debug)
try:
    t = TopSite(debug=debug)
except Exception as e:
    logging.info("error fetching top 1M site list, falling back to pickle method")
    t = TopSite(autoload=False, debug=debug)
    t._load_from_pickle()

scheduler.factory(refresh=app.config["TASK_REFRESH"], debug=debug)
scheduler_obj = scheduler.get_scheduler()
scheduler_obj.start()
analysis_manager.factory(db_obj, scheduler_obj, [v, c], [t, s])

if __name__ == "__main__":
    app.run(host=host, port=port)
