import re
import os
import logging
import time


LOG_LEVEL_INFO = 1

def logi(event, **kwargs):
  log(logging.INFO, event, **kwargs)


def logd(event, **kwargs):
  log(logging.DEBUG, event, **kwargs)


def log(log_level, event, **kwargs):
  # TODO fix line lumber log print
  for name, val in kwargs.items():
    event += " {}={}".format(name, val)
  logger = logging.getLogger(__name__)
  logger.log(log_level, event)


def get_utc():
    return round(time.time() * 1000)

def is_valid_ip_address(address):
  result = True
  match_obj = re.search(
      r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", address)
  if match_obj is None:
      result = False
  else:
    for value in match_obj.groups():
      if int(value) > 255:
        result = False
        break
  return result

def setup_logging(log_level, log_path, log_dir):
    stream_handler = logging.StreamHandler()
    log_level = logging.INFO
    if log_level == 0:
      log_level = logging.DEBUG
    elif log_level == 2:
      log_level = logging.WARN
    elif log_level == 3:
      log_level = logging.ERROR
    elif log_level == 4:
      log_level = logging.CRITICAL
    stream_handler.setLevel(log_level)
    if log_path and log_dir:
      logging.basicConfig(level=log_level,
                          format='%(filename)s:%(lineno)s %(asctime)s %(levelname)s %(message)s',
                          handlers=[logging.FileHandler(log_path, mode='a'),
                                    stream_handler])
      logd("Log location", path=log_path, exists=os.path.exists(log_dir))
    else:
      logging.basicConfig(level=log_level,
                          format='%(filename)s:%(lineno)s %(asctime)s %(levelname)s %(message)s',
                          handlers=[stream_handler])
