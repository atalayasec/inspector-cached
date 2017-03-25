import json

import requests

from named_logger import NamedLogger
from errors import AnalyserUpstreamError, AnalyserConfigurationError, AnalyserResponseError


class BaseAnalyser(NamedLogger):
    """Base class for a remote-service based analyser. This class handles remote
    authentication, creation, retrieval and scoring for remote-based services.
    It MUST be inherited to specialize it for the current service. A remote service
    might be Virustotal, a remote Cuckoo installation or any service that allows
    file/url submission for scan and that provides some sort of scan result.
    Required methods are:
        new()
            a method that performs the required http calls to trigger creation of a new
            analysis task on the remote service. it will return the remote service_id tha
            uniquely identifies this analysis task on the remote service for future
            retrieval an query
        score(task)
            given an already completed analysis task it calculates a meaningful score
            from the upstream data and provides it to the score_creation utility function
            that formats it to an api-friendly representation
        view(type, task_id)
            receives the task type (that can be ignored if the remote api does not
            differentiate on task type upon submission) and returns the analysis
            data by querying the remote service via http
    Two local isntances that must be specified by the inheriting class are the __servicename__,
    used to identify the service via a simple string name and the __serviceresult__ that must
    be a model class that identifies the db mapping object in which to store the type of
    results that will be available from this analysis"""
    __servicename__ = None
    __serviceresult__ = None

    def __init__(self, username=None, password=None, apikey=None, debug=False):
        if not self.__servicename__ or not self.__serviceresult__:
            raise ValueError("abstract class, call one of its implementations")
        self.debug = debug
        self.logger = self.setup_logger(
            debug, "created analyser for {} db result model {}".format(
                self.__servicename__, self.__serviceresult__))
        if (password and not username) or (username and not password):
            raise AnalyserConfigurationError(
                "must provide both username or password or neither")
        self.auth = (username, password) if username and password else None
        self.apikey = apikey

    def is_auth_configured(self):
        return (self.apikey and len(self.apikey) > 1) or (self.auth and len(self.auth[0]) > 1 and len(self.auth[1]) > 1)

    def __load_json(self, response):
        """Internal utility function to load json data from the http call"""
        if len(response.text) < 1:
            return {}
        try:
            return response.json()
        except json.JSONDecodeError as e:
            raise AnalyserResponseError("error decoding response: {}".format(
                e))
        except KeyError:
            raise AnalyserResponseError(
                "task id not found in response: {}".format(response.text))
        except IndexError:
            raise AnalyserResponseError(
                "expected more than one task id in response: {}".format(
                    response.text))
        raise Exception("unexpected error in inner __do_post handling")

    def get_name(self):
        return self.__servicename__

    def score(self, task):
        raise NotImplementedError("must subclass and implement score(task)")

    def new(self, *args, **kwargs):
        raise NotImplementedError("must subclass and override new")

    def view(self, *args, **kwargs):
        raise NotImplementedError("must subclass and override view")

    def result_from_data(self, data):
        if not self.__serviceresult__:
            raise NotImplementedError(
                "must subclass and override result_from_data")
        return self.__serviceresult__.from_data(data)

    def do(self, **params):
        """Wrapper for requests"""
        if not self.__servicename__:
            raise ValueError("abstract class, call one of its implementations")
        if "params" not in params:
            params["params"] = {}
        if self.apikey:
            params["params"].update({"apikey": self.apikey})
        if self.auth:
            params.update({"auth": self.auth})
        if self.debug:
            self.logger.debug("running request with: {}".format(params))
        response = requests.request(**params)
        if response.status_code < 200 or response.status_code > 399:
            raise AnalyserUpstreamError(
                "fatal from analyser API: {}".format(response.text),
                response.status_code)
        if self.debug:
            self.logger.debug("upstream response: {}".format(response.json()))
        return self.__load_json(response)
