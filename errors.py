import logging


class AnalyserError(Exception):
    """Base class for Analyser exceptions"""

    def __init__(self, msg):
        logging.getLogger("Analyser").error(msg)
        self.message = msg


class AnalyserUpstreamError(AnalyserError):
    """Specialized error that also contains the HTTP status code. Meant to be used
    by analysers when inTeracting with remote services over http"""

    def __init__(self, msg, statuscode):
        self.message = msg
        self.code = statuscode


class AnalyserConfigurationError(AnalyserError):
    pass


class AnalyserResponseError(AnalyserError):
    pass


class AnalyserParameterError(AnalyserError):
    pass


class AnalyserDbError(AnalyserError):
    pass
