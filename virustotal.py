import json

from base_analyser import BaseAnalyser
from constants import task_types
from errors import AnalyserResponseError, AnalyserParameterError

from models import AnalyserResult
from utils import score_creator


class Virustotal(BaseAnalyser):
    """Specialized analyser based on the Virustotal service at https://www.virustotal.com
    This class handles all the http requests to the remote service and loads the
    responses from the json representation. A virustotal api key is required,
    currently only the base free APIs are supported. Documentation at https://www.virustotal.com/it/documentation/public-api/"""
    __servicename__ = "virustotal"
    __serviceresult__ = AnalyserResult
    __logname__ = "virustotal_analyser"

    def __init__(self, apikey, debug=False):
        self.baseurl = "https://www.virustotal.com"
        super(Virustotal, self).__init__(apikey=apikey, debug=debug)
        self._super = super(Virustotal, self)
        self.logger.debug(
            "created Virustotal class with api endpoint {} (auth: {})".format(
                self.baseurl, apikey if debug else "hidden"))

    def __check_upstream(self, task):
        """Internal utility function to check for the hash of the submitted file
        to the service before resubmitting for rescan, for api compliance"""
        data = self.view(task.task_type, task.hash)
        resp_code = data.get('response_code')
        if resp_code == 1:
            return data
        return None

    def update_api_key(self, apikey):
        self.logger.debug("updating apikey to {}".format(apikey if self.debug else "hidden"))
        self.apikey = apikey

    def new_from_hash(self, task):
        data = self.__check_upstream(task)
        service_id = data.get("resource", None)
        return service_id

    def new(self, task):
        cached_data = None
        if task.url_type():
            params = {
                "method": "POST",
                "url": "{}/vtapi/v2/url/scan".format(self.baseurl),
                "files": {
                    "url": ("", task.url)
                }
            }
        elif task.file_type():
            cached_data = self.__check_upstream(task)
            params = {
                "method": "POST",
                "url": "{}/vtapi/v2/file/scan".format(self.baseurl),
                "files": {
                    "file": (task.filename, task.filedata)
                }
            }
        else:
            raise AnalyserParameterError(
                "unsupported task type {}: supported ones are {}".format(
                    task.task_type, task_types))
        if not cached_data:
            jdata = self._super.do(**params)
        else:
            jdata = cached_data
        service_id = jdata.get("resource", None)
        if not service_id:
            raise AnalyserResponseError(
                "resource not found in response: {}".format(jdata))
        return service_id

    def update_from_data(self, result, data):
        """Load the provided virustotal """
        resp_code = data.get('response_code')
        if resp_code == 1:
            # item present and scan completed
            n_found = data.get("total")
            scans = data.get("scans", [])
            if not n_found:
                n_found = len(scans)
                self.logger.warn(
                    "no total found, counting the result set ({}) but this might mean api change".
                    format(n_found))
            positives = sum([x.get("detected") for x in scans.values()])
            score = (positives * 100) / n_found
            result.update(data, score, True)
        else:
            if self.debug:
                self.logger.debug("not analysed yet, skipping")

    def score(self, task):
        this = task.get_result(self.__servicename__)
        if not this:
            self.logger.warn("no result found for task {}".format(task.id))
            return None
        try:
            json_result = json.loads(this.result.replace("'", "\""))
        except Exception as e:
            self.logger.error("{}".format(e))
            json_result = {}
        return score_creator(self.__servicename__, this.float_result, {
            "total": json_result.get("total"),
            "positives": json_result.get("positives"),
            "scan_date": json_result.get("scan_date")
        })

    def view(self, _type, task_id):
        """Returns information for the specified task or an error if that task is not found"""
        if _type not in task_types:
            raise AnalyserParameterError(
                "unsupported task type {}: supported ones are {}".format(
                    _type, task_types))
        return self._super.do(**{
            "method": "GET",
            "url": "{}/vtapi/v2/{}/report".format(self.baseurl, _type),
            "params": {
                "resource": task_id,
            }
        })
