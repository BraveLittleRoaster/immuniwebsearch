import coloredlogs
import logging
import verboselogs

banner = f"""
"""

# Create a logger object.
logger = logging.getLogger("OmniScan")


class LVL:
    NOTSET = 0
    SPAM = 5
    DEBUG = 10
    VERBOSE = 15
    INFO = 20
    NOTICE = 25
    WARNING = 30
    SUCCESS = 35
    ERROR = 40
    CRITICAL = 50


def setup(level):
    coloredlogs.install(level=level)
    verboselogs.install()
