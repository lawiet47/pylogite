import logging
from colorlog import ColoredFormatter

LOG_LEVEL = logging.INFO
LOGFORMAT = "%(log_color)s%(levelname)s %(reset)s%(message)s"
logging.root.setLevel(LOG_LEVEL)
formatter = ColoredFormatter(LOGFORMAT,
                             datefmt=None,
                             reset=True,
                             log_colors={
                                 '[V]': 'thin_green',
                                 #'DEBUG': 'thin_white',
                                 '[!]': 'thin,yellow',
                                 '[*]': 'thin_cyan',
                                 '[X]': 'thin_red'
                             }
                             )

INFO = 25
SUCCESS = 30
ERROR = 35
WARNING = 40
logging.addLevelName(SUCCESS, "[V]")
logging.addLevelName(INFO, "[*]")
logging.addLevelName(ERROR, "[X]")
logging.addLevelName(WARNING, "[!]")

stream = logging.StreamHandler()
stream.setLevel(LOG_LEVEL)
stream.setFormatter(formatter)
log = logging.getLogger()
log.setLevel(LOG_LEVEL)
log.addHandler(stream)
