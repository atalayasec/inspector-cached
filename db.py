"""Database and session handling module, contains all classes related to
database handling and session creation/usage/teardown"""
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker, eagerload

from models import Base, AnalysisResult, ValidatorResult, AnalyserResult, Task, poly_load_list
from named_logger import NamedLogger


class sessioncontroller(object):
    """Simple context manager that allows session operations to be contained
    in a with statement. Parameters are:
        close: default to True, if False the session will not be closed
        after the context manager exists, allowing the object to remain
        bound to an open session. Use with care.
        expire_on_commit: defaults to True, if False the objects will
        not be expired and querying operations will still be possible,
        provided the current session has not been closed.
    Refer to the sessionmaker() sqlalchemy documentation for more information
    http://docs.sqlalchemy.org/en/latest/orm/session_api.html#sqlalchemy.orm.session.sessionmaker"""

    def __init__(self, sessionmaker, close=True, expire_on_commit=True):
        self.session = sessionmaker(expire_on_commit=expire_on_commit)
        self.close = close

    def __enter__(self):
        return self.session

    def __exit__(self, type, value, traceback):
        self.session.commit()
        if self.close:
            self.session.close()


class DB(NamedLogger):
    """Database handler class, it receives some keyword arguments as
        anew: if True, it will drop all the tables and reinit the database from
        scratch upon object creation, useful for schema updates or if you do now
        value your data
        debug: enables debug
        db_debug: enables echo of database level calls with SQL output"""
    __logname__ = "db"

    def __init__(self,
                 user,
                 password,
                 host,
                 port,
                 dbname,
                 anew=False,
                 debug=False,
                 db_debug=False):
        self.dbuser = user
        self.dbpass = password
        self.dbhost = host
        self.dbport = port
        self.dbname = dbname
        self.debug = debug
        self.logger = self.setup_logger(
            debug,
            first_msg="creating db object for {}".format(
                self.__format_connstring()))
        self.engine = create_engine(self.__format_connstring(), echo=db_debug)
        self.__init_tables(anew)

    def __format_connstring(self):
        return 'postgresql+psycopg2://{}:{}@{}:{}/{}'.format(
            self.dbuser, self.dbpass, self.dbhost, self.dbport, self.dbname)

    def get_engine_url(self):
        return self.__format_connstring()

    def get_session(self, expire_on_commit=True):
        """Returns a local session that can expire_on_commit the objects, please
        see the sqlalchemy sessionmaker documentation"""
        Session = sessionmaker(
            bind=self.engine, expire_on_commit=expire_on_commit)
        return Session()

    def __init_tables(self, anew):
        """Internal function to drop and create all tables"""
        if anew:
            for tbl in reversed(Base.metadata.sorted_tables):
                self.engine.execute(tbl.delete())
        Base.metadata.create_all(bind=self.engine, checkfirst=True)

    def save(self, obj):
        """If the received object is bound to a session, the inspect module
        is used to use that session to save the item, otherwise a new temporary
        session is created"""
        s = inspect(obj).session
        if not s:
            with sessioncontroller(self.get_session) as session:
                session.add(obj)
        else:
            s.commit()

    def save_with_bind(self, obj):
        """Saves and object allowing it to be re-used in the code. Use with caution
        as the local values are NOT refreshed and the underlying session is kept
        open"""
        with sessioncontroller(
                self.get_session, close=False,
                expire_on_commit=False) as session:
            session.add(obj)

    def delete(self, obj):
        with sessioncontroller(self.get_session) as session:
            session.delete(obj)

    def get_task_by_id(self, task_id, close=True, expire_on_commit=True):
        """Retrieve a task by its internal id, can return a detached or attached object
        based on teh close and expire_on_commit options. Please see the sessionmaker documeNtation
        for their meaning"""
        with sessioncontroller(
                self.get_session, close=close,
                expire_on_commit=expire_on_commit) as session:
            t = session.query(Task).options(
                eagerload(Task.result.of_type(poly_load_list))).get(task_id)
            if not t:
                if self.debug:
                    self.logger.debug(
                        "request for non existing task id {}".format(task_id))
            return t
