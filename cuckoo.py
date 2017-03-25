from base_analyser import BaseAnalyser
from errors import AnalyserResponseError, AnalyserParameterError

from constants import task_types
from utils import score_creator

# plugin storage type
from models import AnalyserResult
from errors import AnalyserUpstreamError


class Cuckoo(BaseAnalyser):
    """Specialization of the analyser for the cuckoo service. It handles all
    http traffic to and from the remote service and provides a simple score, the
    MalScore in cuckoo parlance. See http://docs.cuckoosandbox.org/en/latest/usage/api/
    for the latest api documentation"""
    __servicename__ = "cuckoo"
    __serviceresult__ = AnalyserResult
    __logname__ = "cuckoo_analyser"

    def __init__(self, baseurl, username=None, password=None, debug=False):
        self.baseurl = baseurl
        super(Cuckoo, self).__init__(
            username=username, password=password, debug=debug)
        self._super = super(Cuckoo, self)
        self.logger.debug(
            "created {} class with api endpoint {} (auth: {})".format(
                self.__servicename__, baseurl, username and password))

    def update_credentials(self, username, password):
        self.logger.debug("updating username {} and password".format(username, password if self.debug else "hidden"))
        self.auth = (username, password)

    def new(self, task):
        if task.url_type():
            params = {
                "method": "POST",
                "url": "{}/tasks/create/url".format(self.baseurl),
                "files": {
                    "url": ("", task.url)
                }
            }
        elif task.file_type():
            params = {
                "method": "POST",
                "url": "{}/tasks/create/file".format(self.baseurl),
                "files": {
                    "file": (task.filename, task.filedata)
                }
            }
        else:
            raise AnalyserParameterError(
                "unsupported task type {}: supported ones are {}".format(
                    task.task_type, task_types))
        jdata = self._super.do(**params)
        if "task_ids" in jdata:
            task_id = jdata.get("task_ids")[0]
        elif "task_id" in jdata:
            task_id = jdata.get("task_id")
        else:
            raise AnalyserResponseError(
                "cuckoo task id not found in {}".format(jdata))
        return task_id

    def update_from_data(self, result, data):
        if len(data) < 1:
            return
        malscore = "malscore"
        malware_score = data.get(malscore)
        if not malware_score:
            raise AnalyserResponseError(
                "expected \"{}\" to be in rensponse keys, found {}".format(
                    malscore, data.keys()[:]))
        result.update(data, malware_score, True)

    def score(self, task):
        this = task.get_result(self.__servicename__)
        if not this:
            self.logger.warn("no result found for task {}".format(task.id))
            return None
        return score_creator(self.__servicename__, this.float_result, {})

    def view(self, _type, task_id):
        """Returns information for the specified task or an error if that task is not found"""
        try:
            return self._super.do(**{
                "method": "GET",
                "url": "{}/tasks/report/{}".format(self.baseurl, task_id)
            })
        except AnalyserUpstreamError as e:
            if "404" in str(e.code):
                return None
