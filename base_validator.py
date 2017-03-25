from named_logger import NamedLogger


class BaseValidator(NamedLogger):
    """Base class for a validator analysis. This analysis does not require some remote
    service call or outside interaction but can be performed only on the task data itself.
    The most common case is for an URL, where there are some properties that can be inferred
    by only looking at the url itself"""
    __servicename__ = None
    __serviceresult__ = None
    __logname__ = None

    def get_name(self):
        return self.__servicename__

    def score(self, task):
        """Scoring function for the validator, will check wether the validation for the
        task data has passed and use the score_creator utility function to create a response
        that can be forwarded to the calling api"""
        raise NotImplementedError("must subclass and implement score(task)")

    def validate(self, task):
        """Validation function that performs the analisys. It should return a boolean
        value."""
        raise NotImplementedError("must subclass and implement validate")
