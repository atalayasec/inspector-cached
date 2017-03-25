import logging
import sys


class NamedLogger(object):
    """Named Logger with default settings. The __logname__ class attribute will
    be used to name messages coming from any subclass"""
    __logname__ = None

    def setup_logger(self, debug=False, first_msg=None):
        if not self.__logname__:
            raise NotImplementedError(
                "must subclass this logging class and define __logname__ property"
            )
        logger = logging.getLogger(self.__logname__)
        level = logging.DEBUG if debug else logging.INFO
        logger.setLevel(level)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(level)
        logger.addHandler(ch)
        if first_msg:
            logger.debug(first_msg)
        return logger
