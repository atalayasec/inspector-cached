"""Sqlalchemy database representation models"""
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Enum, LargeBinary, ForeignKey, Boolean, Float, DateTime
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import synonym, relationship, with_polymorphic

import logging
import sys
import io
import json

from utils import hash_bytes
from constants import task_types

Base = declarative_base()

_logger = logging.getLogger("db_object")
_logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
_logger.addHandler(ch)


class AnalyserDbError(Exception):
    pass


class AnalysisResult(Base):
    """Polymorphic class to represent any analyser result, be it from a validator or
    from an analyser proper, it contains the references to the task itself and the service
    name that represents the analyser or validator that returned this result"""
    __tablename__ = "result"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task = relationship("Task", back_populates="result")
    task_id = Column(Integer, ForeignKey('task.id'))
    service_name = Column(String)
    type = Column(String)

    __mapper_args__ = {
        'polymorphic_identity': 'result',
        'polymorphic_on': type
    }


class ValidatorResult(AnalysisResult):
    """Binary result class, it reports only a boolean value for the result"""
    __tablename__ = "validator_result"

    id = Column(Integer, ForeignKey('result.id'), primary_key=True)
    validated = Column(Boolean)

    __mapper_args__ = {'polymorphic_identity': 'validator_result'}

    def __str__(self):
        return "{} result for task id {} validated {}".format(
            self.service_name, self.task_id, self.validated)


class AnalyserResult(AnalysisResult):
    """Concrete remote service result class, it contains the result in string form - the body
    of the service response - together with a  float_result, usually derived on the values
    that are returned. It also contains the name of the remote service and the completed flag
    to signal that the remote service consdiers the analysis task complete and the further
    queries will return the same data"""
    __tablename__ = "analyser_result"

    id = Column(Integer, ForeignKey('result.id'), primary_key=True)
    result = Column(String)
    float_result = Column(Float)
    remote_service_id = Column(String)
    completed = Column(Boolean)

    def update(self, result, float_result, completed):
        _logger.info("updating: float_result {} completed {}".format(
            float_result, completed))
        self.result = json.dumps(result)
        self.float_result = float_result
        self.completed = completed

    __mapper_args__ = {'polymorphic_identity': 'analyser_result'}

    def __str__(self):
        return "{} result for task id {} numeric {} string {}".format(
            self.service_name, self.task_id, self.float_result, self.result)


class Task(Base):
    """Task class that defines an analysis task for a FILE or URL resource.
    The task is timestamped, based on the time of creation by the local system, and
    a result polymorphic value that represents its result for each queried analyser and
    validator."""
    __tablename__ = "task"

    id = Column(Integer, primary_key=True, autoincrement=True)
    result = relationship(
        "AnalysisResult", back_populates="task", cascade="all, delete-orphan")
    timestamp = Column(DateTime)
    task_type = Column(Enum(*task_types, name="task_types"))
    completed = Column(Boolean)
    url = Column(String)
    filename = Column(String)
    filedata = Column(LargeBinary)
    _hash = Column(String)
    hash = synonym('_hash', descriptor=hash)

    def __init__(self, _type, url=None, filename=None, filedata=None, from_hash=False):
        if _type not in task_types:
            raise AnalyserDbError("task of type {} must be in {}".format(
                _type, ",".join(task_types)))
        self.task_type = _type
        if url and _type == "url":
            self.url = url
        elif filedata and _type == "file":
            self.filedata = filedata
            if not filename:
                filename = hash_bytes(filedata)
            self.filename = filename
        else:
            if not from_hash:
                raise ValueError(
                    "must provide either url or filedata for analisys task")
        # fake assign just to trigger execution
        self.hash = ""

    def __str__(self):
        return "Task {} at {} for {}".format(self.id, self.timestamp, self.url
                                             if self.url_type() else
                                             self.filename)
    @classmethod
    def from_hash(cls, h):
        t = cls("file", from_hash=True)
        t.hash = h
        t._hash = h
        return t

    def data_as_buffer(self):
        return io.BytesIO(self.filedata)

    @hybrid_property
    def hash(self):
        return self._hash

    @hash.setter
    def hash(self, value):
        if self.url_type():
            self._hash = hash_bytes(self.url.encode())
        elif self.file_type():
            if self.filedata:
                self._hash = hash_bytes(self.filedata)

    def url_type(self):
        return self.task_type == "url"

    def file_type(self):
        return self.task_type == "file"

    def set_completed(self, completed=True):
        self.completed = completed

    def is_completed(self):
        return all([
            x.completed == True for x in self.result
            if isinstance(x, AnalyserResult)
        ])

    def get_result(self, service_name):
        for x in self.result:
            if x.service_name == service_name:
                return x
        return None

    def string_id(self):
        return self.hash


poly_load_list = with_polymorphic(
    AnalysisResult, [ValidatorResult, AnalyserResult], flat=True)
