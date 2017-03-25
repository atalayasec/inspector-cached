"""
This module contains the AnalysisManager class. It is operated as a singleton
and should only be built via the factory method and getted via the get_manager one.
Multiple instantiations can result in problems on the database side
The constructor of this class receives a db instance (for task persistence/query),
an instance of the scheduler (for watch/unwatch operation on tasks) and two
sets of analysers and validators."""
from datetime import datetime
from os.path import exists
import pickle

from models import Task, ValidatorResult, AnalyserResult
from constants import TASK_TYPE_URL, TASK_TYPE_FILE
from errors import AnalyserDbError
from named_logger import NamedLogger

__manager = None


class AnalysisManager(NamedLogger):
    __logname__ = "analysis_manager"
    __credsfile__ = "./.credentials"

    def __init__(self, db, scheduler, analysers, validators, debug=True):
        self.db = db
        self.scheduler = scheduler
        self.analysers = analysers
        self.validators = validators
        self.debug = debug
        self.logger = self.setup_logger(
            debug,
            first_msg="created analysis manager with analysers {} validators {}".
            format([x.__servicename__ for x in self.analysers],
                   [x.__servicename__ for x in self.validators]))
        self.__load_credentials()

    def __load_credentials(self):
        # FIXME: bad method, bad idea, bad implementation
        if not exists(self.__credsfile__):
            return
        try:
            data = pickle.load(open(self.__credsfile__, "rb"))
            for service_name in [x.__servicename__ for x in self.analysers]:
                self.logger.info("loading stored credentials for {}".format(service_name))
                service_data = data.get(service_name, {})
                if "APIKEY" in service_data:
                    self.logger.info("loading stored apikey for {}".format(service_name))
                    self.update_api_key(service_name, service_data.get("APIKEY"), loaded=True)
                if "USERNAME" in service_data:
                    self.logger.info("loading stored username for {}".format(service_name))
                    self.update_credentials(service_name, service_data.get("USERNAME"), None, loaded=True)
                if "PASSWORD" in service_data:
                    self.logger.info("loading stored password for {}".format(service_name))
                    self.update_credentials(service_name, None, service_data.get("PASSWORD"), loaded=True)
        # catchall exception: if anything fails, just log and do nothing, the user will configure it again
        except Exception as e:
            self.logger.info("load_credentials: {}".format(e))

    def __save_credentials(self, service, apikey=None, username=None, password=None):
        # FIXME: possibly even worse than __load_credentials
        data = {}
        if not exists(self.__credsfile__):
            self.logger.info("creating credentials file")
        else:
            try:
                data = pickle.load(open(self.__credsfile__,"rb"))
            except Exception as e:
                self.logger.info("load in save_credentials: {}".format(e))
                return

        if service not in data:
            self.logger.info("creating credentials stanza for service {}".format(service))
            data[service] = {}

        if apikey:
            self.logger.info("saving apikey for {}".format(service))
            data[service]["APIKEY"] = apikey
        if username:
            self.logger.info("saving username for {}".format(service))
            data[service]["USERNAME"] = username
        if password:
            self.logger.info("saving password for {}".format(service))
            data[service]["PASSWORD"] = password

        try:
            pickle.dump(data, open(self.__credsfile__, "wb"))
        except Exception as e:
            self.logger.info("dump in save_credentials: {}".format(e))

    def usable_analysers(self):
        return [x for x in self.analysers if x.is_auth_configured()]

    def usable_analysers_names(self):
        return [x.__servicename__ for x in self.analysers if x.is_auth_configured()]

    def get_analyser(self, name):
        for x in self.analysers:
            if x.__servicename__ == name:
                return x
        return None

    def update_api_key(self, service, apikey, loaded=False):
        for a in self.analysers:
            if a.__servicename__ == service:
                a.update_api_key(apikey)
                if not loaded:
                    self.__save_credentials(service, apikey=apikey)

    def update_credentials(self, service, username, password, loaded=False):
        for a in self.analysers:
            if a.__servicename__ == service:
                if not username:
                    self.logger.debug("only updating password")
                    _user = a.auth[0]
                    a.update_credentials(_user, password)
                elif not password:
                    self.logger.debug("only updating username")
                    _pass = a.auth[1]
                    a.update_credentials(username, _pass)
                elif not username and not password:
                    raise ValueError("either username or password must not be null")
                else:
                    self.logger.debug("updating username and password")
                    a.update_credentials(username, password)
                if not loaded:
                    self.__save_credentials(service, password=password, username=username)

    def new_url(self, url):
        """Creates a new url task, persists it on the db and
        launches both validators and analysers on it, adding the relevant
        watchers to update the local view of the task state with the remote
        one coming down from the remote services. This call will return the
        task object bound to a session, any operation on it should not be
        performed manually"""
        timestamp = datetime.now()
        task = Task(TASK_TYPE_URL, url=url)
        task.timestamp = timestamp
        for v in self.validators:
            validated = v.validate(task)
            res = ValidatorResult()
            res.service_name = v.__servicename__
            res.validated = validated
            task.result.append(res)
        for a in self.usable_analysers():
            task_id = a.new(task)
            res = AnalyserResult()
            res.service_name = a.__servicename__
            res.remote_service_id = task_id
            task.result.append(res)
        self.db.save_with_bind(task)
        self.add_task_watcher(task)
        return task

    def new_file(self, filedata, filename=None, from_hash=None):
        """Creates a new file task, persists it on the db and
        launches all available analysers on it, adding the relevant
        watchers to update the local view of the task state with the remote
        one coming down from the remote services. If the from_hash parameter
        is not None only analysers that support the new_from_hash() function
        will be called. This call will return the task object bound to
        a session, any operation on it should not be performed manually"""
        timestamp = datetime.now()
        if from_hash:
            self.logger.info("calling only hash-aware analysers with hash {}".format(from_hash))
            task = Task.from_hash(from_hash)
            task.task_type = TASK_TYPE_FILE
            task.timestamp = timestamp
            for a in self.usable_analysers():
                if hasattr(a, "new_from_hash"):
                    task_id = a.new_from_hash(task)
                    res = AnalyserResult()
                    res.service_name = a.__servicename__
                    res.remote_service_id = task_id
                    task.result.append(res)
            self.db.save_with_bind(task)
            self.add_task_watcher(task)
            return task

        task = Task(TASK_TYPE_FILE, filename=filename, filedata=filedata)
        task.timestamp = timestamp
        for a in self.usable_analysers():
            # FIXME: skip everython, only cuckoo
            if a.__servicename__ != "cuckoo":
                continue
            task_id = a.new(task)
            res = AnalyserResult()
            res.service_name = a.__servicename__
            res.remote_service_id = task_id
            task.result.append(res)
        self.db.save_with_bind(task)
        self.add_task_watcher(task)
        return task

    def add_task_watcher(self, task):
        """Internal use function, exposed for debugging purposes, that
        creates a watcher job on the scheduler for a given _session_ _bound_
        task object"""
        job_id = task.string_id()
        self.logger.info("adding scheduled job id {} function {}".format(
            job_id, self.watch_task))
        self.scheduler.add_interval_job(
            self.watch_task, job_id, job_args=(task.id, ))

    # TODO: add method to scan for uncompleted jobs that are not watched and watch them
    # TODO: add clen method to un-schedule a completed job

    def watch_task(self, task_id):
        """Task analysis function, it's the lower function invoked by the scheduler
        every time it runs. This function will iterate on the list of current
        available analysers and for each perform the view() action on the given
        task. The results, if any, will then be updated in the task object relation
        itself and the result persisted on the database. Once all remote analysis tasks
        have completed the function will remove itself from the scheduler and
        stop analysing already completed objects"""
        task = self.db.get_task_by_id(
            task_id, close=False, expire_on_commit=False)
        if not task:
            raise AnalyserDbError("task id {} not found".format(task.id))
        # iterate on services that require polling
        for current_analyser in self.usable_analysers():
            # load the service result from the result object that refers to the current analyser
            analyser_result = [
                x for x in task.result
                if x.service_name == current_analyser.__servicename__
            ]
            if len(analyser_result) != 1:
                self.logger.warning(
                    "no result for service name {} found for task id {} ".
                    format(current_analyser.__servicename__, task.id))
                continue
            analyser_result = analyser_result[0]
            if analyser_result.completed:
                self.logger.info(
                    "analysis on {} aldready completed, skipping watch".format(
                        analyser_result.remote_service_id))
                continue
            data = current_analyser.view(task.task_type,
                                         analyser_result.remote_service_id)
            if not data:
                self.logger.info("analysis in {} pending".format(
                    analyser_result.remote_service_id))
                continue
            current_analyser.update_from_data(analyser_result, data)
        if task.is_completed():
            task.completed = True
            self.logger.info("current task {} is completed, quitting watch!".
                             format(task.id))
            self.scheduler.remove_job(task.string_id())
        self.db.save(task)

    def view_task(self, task_id):
        """Invoked when the api needs to present the current status of the task
        for a query, it scans the list of all available analysers and validators,
        since the result is now the same, and calls the score(task) action
        for each one, producing a task_desc dict object that represents the current
        view of the task and that can be returned to the calling client"""
        task = self.db.get_task_by_id(task_id, close=False)
        if not task:
            self.logger.debug("task id {} not found!".format(task_id))
            return None
        task_desc = {}
        for a in self.usable_analysers() + self.validators:
            if self.debug:
                self.logger.debug("running score function for {} on task {}".
                                  format(a.get_name(), task.id))
            score = a.score(task)
            if not score:
                continue
            task_desc[a.get_name()] = score
        return task_desc


def factory(db_obj, scheduler, analysers, validators):
    """Module-wide instance constructor, it receives the same parameters of the
    main class init function and instantiates the local copy. This function will
    raise a RuntimeError if invoked twice"""
    global __manager
    if __manager:
        raise RuntimeError("factory creation method invoked twice")
    __manager = AnalysisManager(db_obj, scheduler, analysers, validators)


def get_manager():
    """Getter method for the module wide AnalysisManager singleton-like object.
    If called on an uninitialized module it will raise a ValueError"""
    global __manager
    if not __manager:
        raise ValueError("must first setup the instance via factory()")
    return __manager
