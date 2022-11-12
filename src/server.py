import os
import argparse
import logging
import socket
import errno
import uuid
import jwt
import time
from threading import Thread
from datetime import date
from pyparser import HttpParser, KIND_REQ


JWT_SECRET = "a9ddbcaba8c0ac1a0a812dc0c2f08514b23f2db0a68343cb8199ebb38a6d91e4ebfb378e22ad39c2d01 d0b4ec9c34aa91056862ddace3fbbd6852ee60c36acbf"

DEFAULT_HTTP_PORT = 80

def logi(event, **kwargs):
  log(logging.INFO, event, **kwargs)

def logd(event, **kwargs):
  log(logging.DEBUG, event, **kwargs)

def log(log_level, event, **kwargs):
  for name, val in kwargs.items():
    event += " {}={}".format(name, val)
  logger = logging.getLogger(__name__)
  logger.log(log_level, event)

def get_utc():
    return round(time.time() * 1000)

def send_all(sock, bytes):
  while len(bytes) > 0:
    bytes_sent = sock.send(bytes)
    bytes = bytes[bytes_sent:]

def split_address(dest):
  parts = dest.split(":")
  if len(parts) == 1:
    return (parts[0], DEFAULT_HTTP_PORT)
  return parts[0], int(parts[1])

def compose_request(parser):
  req = "{} {}".format(parser.get_method(), parser.get_path())
  if len(parser.get_query_string()) > 0:
    req += "?{}".format(parser.get_query_string())
  if len(parser.get_fragment()) > 0:
    req += "#{}".format(parser.get_fragment())
  req += " HTTP/{}.{}\r\n".format(parser.get_version()[0], parser.get_version()[1])
  
  # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive
  # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
  parser._headers["Connection"] = "close"
  
  for name, val in parser.get_headers().items():
    if name.startswith("PROXY"):
      continue
    req += "{}: {}\r\n".format(name.title(), val)
  req += "\r\n"
  return str.encode(req)


class ProxyServer:
  def __init__(self, port, buffer_size, max_connections, log_dir, log_level):
    self.log_path = os.path.join(log_dir, "proxy-server.log")
    if not os.path.exists(log_dir):
      os.makedirs(log_dir)
    # Setup logger
    stream_handler = logging.StreamHandler()
    self.log_level = logging.INFO
    if log_level == 0:
      self.log_level = logging.DEBUG
    elif log_level == 2:
      self.log_level = logging.WARN
    elif log_level == 3:
      self.log_level = logging.ERROR
    elif log_level == 4:
      self.log_level = logging.CRITICAL
    stream_handler.setLevel(self.log_level)
    logging.basicConfig(level=self.log_level,
                        format='%(filename)s:%(lineno)s %(asctime)s %(levelname)s %(message)s',
                        handlers=[logging.FileHandler(self.log_path, mode='a'),
                                  stream_handler])
    logd("Log location", path=self.log_path, exists=os.path.exists(log_dir))
    self.server_socket = socket.socket()
    self.server_socket.bind(("0.0.0.0", port))
    self.server_socket.listen(max_connections)
    logi("server started", port=port)
    self.buffer_size = buffer_size

  def accept_new_connections(self):
    while True:
      conn, address = self.server_socket.accept()
      logi("new connection", client=address)
      t = Thread(target=self.process_connection, args=(conn, address))
      t.setDaemon(True)
      t.start()

  def process_connection(self, source_conn, address):
    parser = HttpParser(KIND_REQ)
    # Parse headers:
    request_headers_bytes = b''
    leftover = b''
    while parser.is_headers_complete() == False:
      _chunk = source_conn.recv(self.buffer_size)
      if len(_chunk) == 0:
        logd("End of request", client=address)
        return
      chunk = leftover + _chunk
      ## TODO: bug parser lib does not return correct result for final chunk on headers complete
      consumed = parser.execute(chunk, len(chunk))
      leftover = chunk[consumed:]
      request_headers_bytes += chunk[:consumed]
    # Connect to destination host
    logd("request", bytes=request_headers_bytes)
    dest_conn = socket.socket()
    try:
      destination = parser.get_headers()["host"]
    except:
      ## TODO: return 400 Bad Request instead of exception
      raise
      # pdb.set_trace()

    logd("Connecting", client=address, destination=destination)
    dest_conn.connect(split_address(destination))
    logi("Connected ..", client=address, destination=destination)
    # Modify received headers

    pos = parser._path.find(destination)
    is_full_url = pos != -1
    if is_full_url:
      # keep only path in forwarded request
      parser._path = parser._path[pos + len(destination):]

    # Add JWT token if it is a post request
    self.create_jwt_if_needed(parser)
    # Send (modified?) headers to destionation
    request_headers_bytes = compose_request(parser)
    logd("sending headers", client=address, destination=destination, req=request_headers_bytes, leftover=leftover)

    send_all(dest_conn, request_headers_bytes)
    logd("headers sent ..", client=address, destination=destination)
    send_all(dest_conn, leftover)
    logd("leftover sent ..", client=address, destination=destination)
    # Spawn destination_response_processing
    t = Thread(target=self.destination_response_processing, args=(source_conn, dest_conn, address, destination))
    t.setDaemon(True)
    t.start()
    # Stream rest of the body to destination
    try:
      while True:
        chunk = source_conn.recv(16384)
        logd("sending body", client=address, destination=destination, chunk=chunk)
        if len(chunk) == 0:
          logd("End of request body", client=address)
          # close source_conn in destination_response_processing()
          return
        send_all(dest_conn, chunk)
    except OSError as error:
      ## If it is bad file descriptor that means connection was closeed on the other end
      if error.errno != errno.EBADF:
        raise error
      else:
        logi("connection closed", client=address)
        # TODO close the source_conn
    

  def destination_response_processing(self, source_conn, dest_conn, address, destination):
    while True:
      logd("waiting for next chunk", _from=destination)
      chunk = dest_conn.recv(self.buffer_size)
      if len(chunk) == 0:
        dest_conn.close()
        source_conn.close() # remove in case of HTTP 1.1
        logd("End of response", client=address)
        return
      logd("forward response", _from=destination, chunk=chunk)
      send_all(source_conn, chunk)
      
  def create_jwt_if_needed(self, parser):
    if (parser.get_method() != "POST"):
      return
    current_ts = get_utc()
    crypto_id = str(uuid.uuid4())
    date_today = date.today().strftime("%d.%m.%Y")
    payload_data = {"user": "username",
                    "date": date_today}
    logi("generating Json web token ...", iat=current_ts, jti=crypto_id, date=date_today)
    token_payload = {"iat" : current_ts, "jti" : crypto_id, "payload": payload_data}
    # generate token
    token = jwt.encode(
        payload = token_payload,
        key = JWT_SECRET,
        algorithm = 'HS512'
    )
    logd("JWT token generated", token=token)
    parser.get_headers()["x-my-jwt"] = token
    

if __name__== "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--http_port', help="Port to listen to, default 8000", default=8000, type=int)
  parser.add_argument(
      '--max_conn', help="Maximum allowed connections, default 5", default=5, type=int)
  parser.add_argument(
      '--buffer_size', help="Number of samples to be used, default 8192", default=8192, type=int)
  parser.add_argument(
      '--log_dir', help="Path to the directory where the log files will be created, default ./log", default="./log", type=str)
  parser.add_argument(
      '--log_level', help="0 - DEBUG, 1 - INFO, 2 - WARN, 3 - ERROR, 4 FATAL , default INFO(1)", default=1, type=int)
  args = parser.parse_args()
  max_connection = args.max_conn
  buffer_size = args.buffer_size
  listening_port = args.http_port
  log_dir= args.log_dir
  log_level = args.log_level

  server = ProxyServer(listening_port, buffer_size, max_connection, log_dir, log_level)
  server.accept_new_connections()
