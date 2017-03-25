"""This module currently requires network access to load the static top 1 million
domain list from Alexa, if network connectivity is not available a static top-1m.csv
file is required."""
import requests
import zipfile
import csv
import io
import pickle
from urllib.parse import urlparse

from models import ValidatorResult
from base_validator import BaseValidator
from utils import score_creator

ZIP_URL = "http://s3.amazonaws.com/alexa-static/top-1m.csv.zip"


class TopSite(BaseValidator):
    """This class receives a list of the top 1 million (or any other list in that format),
    extracts the base from the requested url and validates it if the base is found in the list"""
    __servicename__ = "top_validator"
    __serviceresult__ = ValidatorResult
    __logname__ = __servicename__

    def __init__(self, url=ZIP_URL, autoload=False, debug=False):
        self.url = url
        self.top = {}
        self.debug = debug
        self.logger = self.setup_logger(
            debug,
            first_msg="created top 1 million validator with url {}".format(
                ZIP_URL))
        if autoload:
            self.__load()

    def _load_from_pickle(self, f="top_1m.pickle"):
        """Internal function to load the file from pickle should the
        s3 download page be unavailable"""
        self.top = pickle.load(open(f, "rb"))

    def __load(self):
        """Receives a zipped CSV file"""
        resp = requests.get(self.url)
        if resp.status_code != requests.codes.ok:
            if self.debug:
                self.logger.debug("response code {} message {}".format(
                    resp.status_code, resp.text))
            raise ValueError("upstream error ({}): {}".format(resp.status_code,
                                                              resp.text))
        content = io.BytesIO(resp.content)
        zfile = zipfile.ZipFile(content)
        fname = zfile.namelist()[0]
        fdata = io.TextIOWrapper(io.BytesIO(zfile.read(fname)))
        reader = csv.reader(fdata)
        for row in reader:
            self.top[row[1]] = True

    def init(self):
        self.__load()

    def __is_top(self, url):
        if self.debug:
            self.logger.debug("top for url {}".format(url))
        return self.top.get(url, False)

    def validate(self, task):
        if not task.url_type():
            raise ValueError("this validator only accepts url tasks")
        parsed = urlparse(task.url)
        if not parsed:
            raise ValueError("not an url")
        if parsed.scheme not in ["http", "https"]:
            raise ValueError("non-url passed")
        return self.__is_top(parsed.hostname)

    def score(self, task):
        this = task.get_result(self.__servicename__)
        if not this:
            self.logger.warn("no result found for task {}".format(task.id))
            return None
        return score_creator(self.__servicename__, 1
                             if this.validated else 0, {})
