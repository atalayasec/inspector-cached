"""
This class is meant to be operated as a singleton, and should only
be built via the factory method and retrieved via the get_scheduler one.
"""
from named_logger import NamedLogger
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.base import JobLookupError

__scheduler = None


class Scheduler(NamedLogger):
    """Scheduler class creates a default system scheduler with a default refresh
    time and utility functions to create and remove jobs. All jobs are identified
    by an id string."""
    __logname__ = "scheduler"

    def __init__(self, refresh=3600, debug=False):
        self.scheduler = BackgroundScheduler()
        self.refresh = refresh
        first_msg = "created scheduler with refresh period {}".format(refresh)
        self.logger = self.setup_logger(debug=debug, first_msg=first_msg)

    def start(self):
        self.logger.info("starting scheduler")
        self.scheduler.start()

    def stop(self):
        self.logger.info("stopping scheduler")
        self.scheduler.pause()

    def add_interval_job(self, func, job_id, job_args=None):
        """Adds periodic job with the default refresh period"""
        self.logger.info("adding job {} args {}".format(job_id, job_args))
        self.scheduler.add_job(
            func,
            trigger="interval",
            id=job_id,
            seconds=self.refresh,
            args=job_args)

    def remove_job(self, job_id):
        """Stops and removes a given job"""
        self.logger.info("removing job {}".format(job_id))
        try:
            self.scheduler.remove_job(job_id)
        except JobLookupError:
            self.logger.error("no such job {}".format(job_id))


def factory(*args, **kwargs):
    global __scheduler
    __scheduler = Scheduler(*args, **kwargs)


def get_scheduler():
    global __scheduler
    return __scheduler
