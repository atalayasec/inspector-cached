from urllib.parse import urlparse
import socket
import ssl

from models import ValidatorResult
from base_validator import BaseValidator

from utils import score_creator


class SSLSite(BaseValidator):
    """The SSL Validator tries to validate the certificate, for an HTTPS link,
    by trying to verify the server cert with the configurable ca_bundle file usually
    shipped with the operating system. This validator requires network connectivity.
    It is assumed that the standard python ssl module built with reasonably recent
    openssl versions will be used for the connection"""
    __servicename__ = "ssl_validator"
    __serviceresult__ = ValidatorResult
    __logname__ = __servicename__

    def __init__(self,
                 ca_bundle="/etc/ssl/certs/ca-certificates.crt",
                 debug=False):
        self.debug = debug
        self.ca_bundle = ca_bundle
        self.logger = self.setup_logger(
            debug,
            first_msg="created ssl validator with ca {}".format(ca_bundle))

    def __load(self):
        pass

    def init(self):
        self.__load()

    def __check_ssl(self, host, port):
        """This method calls the ssl module to perform the initial ssl handshake
        upon connection to retrieve the underlying library error, if any, and then
        immediately closes the connection"""
        s = socket.socket()
        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        try:
            context.load_verify_locations(self.ca_bundle)
        except FileNotFoundError:
            return False, "ca bundle file not found"
        except ssl.SSLError:
            return False, "cannot load certificate"
        except:
            return False, "unknown error loading ca bundle file"
        ss = context.wrap_socket(s, server_hostname=host)
        try:
            ss.connect((host, port))
            ss.close()
            return True, ""
        except ssl.SSLError:
            return False, "ssl handshake error"
        except ssl.CertificateError:
            return False, "certificate validation error"
        return False, "unknown unhandled error"

    def validate(self, task):
        if not task.url_type:
            raise ValueError("only url tasks are supported by this validator")
        parsed = urlparse(task.url)
        if parsed.scheme not in ["http", "https"]:
            raise ValueError("non-url passed")
        if parsed.scheme != "https":
            raise ValueError("non-HTTPS urls do not require ssl validation")
        port = parsed.port
        if not port:
            port = 443
        ok, msg = self.__check_ssl(parsed.hostname, port)
        if self.debug:
            self.logger.debug("checking {} valid ssl {}".format(task.url, ok))
        return ok

    def score(self, task):
        this = task.get_result(self.__servicename__)
        if not this:
            self.logger.warn("no result found for task {}".format(task.id))
            return None
        return score_creator(self.__servicename__, 1
                             if this.validated else 0, {})
