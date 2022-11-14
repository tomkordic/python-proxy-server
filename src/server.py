import gevent
import gevent.server
import gevent.monkey
import os
import argparse
import socket
import errno
import uuid
import jwt
import netifaces as ni
from threading import Thread, Lock
from datetime import date, datetime
from pyparser import HttpParser, KIND_REQ
from template import status_page_template, response_headers_template
from utils import logd, logi, setup_logging, get_utc
from constants import JWT_SECRET


DEFAULT_HTTP_PORT = 80

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
  def __init__(self, port, buffer_size, max_connections, log_dir, log_level, async_mode):
    self.async_mode = async_mode
    if self.async_mode:
        gevent.monkey.patch_all()
    else:
      self.lock = Lock()
    self.log_path = os.path.join(log_dir, "proxy-server.log")
    if not os.path.exists(log_dir):
      os.makedirs(log_dir)
    setup_logging(log_level, self.log_path, log_dir)
    self.server_socket = socket.socket()
    self.server_socket.bind(("0.0.0.0", port))
    self.server_socket.listen(max_connections)
    logi("server started", port=port)
    self.buffer_size = buffer_size
    self.start_time = get_utc()
    self.number_of_requests = 0
    self.ip_trickery()

  def ip_trickery(self):
    ## requests lib uses SSL sockets so import only after we have done monkey patch.
    from requests import get
    from requests.exceptions import ConnectionError
    # determine external ip.
    try:
      self.extern_ip = get('https://api.ipify.org').content.decode('utf8')
      logd("External ip detected:", external_ip=self.extern_ip)
    except ConnectionError as error:
      logd("No internet connection, expecting only requests from the local network.")
      self.extern_ip = "unknown"
    ## get ip on every local interface
    self.local_ips = ["0.0.0.0"]
    for interface in ni.interfaces():
      try:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        logd("Local address found", interface=interface, ip=ip)
        self.local_ips.append(ip)
      except ModuleNotFoundError as error:
        logd("ModuleNotFoundError", interface=interface, error=str(error))
      except ValueError as error:
        logd("ValueError", interface=interface, error=str(error))
      except KeyError:
        logd("No IP", interface=interface)
    logi("Interfaces", extern_ip=self.extern_ip, local_ips=self.local_ips)

  def accept_new_connections(self):
    while True:
      conn, address = self.server_socket.accept()
      logi("new connection", client=address)
      if self.async_mode:
        g = gevent.spawn(self.process_connection, conn, address)
      else:
        t = Thread(target=self.process_connection, args=(conn, address))
        t.setDaemon(True)
        t.start()

  def process_connection(self, source_conn, address):
    logd("processing connection", address=address)
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
    try:
      parser.get_headers()["host"]
    except:
      self.serve_response(source_conn, address, 400, "BAD REQUEST")
      return
    ## TODO detect https request and send 406 not allowed
    if self.is_proxy_request(parser):
      logi("Processing proxy request", address=address)
      self.process_proxy_request(
          source_conn, address, parser, request_headers_bytes, leftover)
    else:
      logi("Processing non proxy request", address=address)
      self.process_request(source_conn, address, parser)

  def is_proxy_request(self, parser):
    host = parser.get_headers()["host"]
    # try to resolve the host name
    try:
      resolved_host_ip = socket.gethostbyname(host)
      logi("Host name resolved", host=host, host_ip=resolved_host_ip)
      host = resolved_host_ip
    except:
      logi("failed to resolve host", host=host)
    host_match = False;
    if host.lower().find(self.extern_ip) != -1:
      host_match = True
    for local_ip in self.local_ips:
      if host.lower().find(local_ip) != -1:
        host_match = True
    ## TODO maybe include a header checkup also
    # for name, val in parser.get_headers().items():
    #   if name.lower().startswith("proxy"):
    #     return True
    return not host_match

  def process_request(self, source_conn, address, parser):
    request_url = parser.get_url()
    logi("Request received", url=request_url)
    if request_url.find("?") != -1:
      request_url = request_url.split("?")[0]
    if request_url.lower() == "/status":
      logi("serving status page")
      self.serve_status_page(source_conn, address)
    else:
      self.serve_response(source_conn, address, 404, "NOT FOUND")

  def serve_response(self, source_conn, address, status, status_message):
    response_headers = response_headers_template.substitute({
        "status_code": str(status),
        "status_message": status_message,
        "content_type": "TEXT/HTML",
        "content_length": "0"})
    logi("Serving response", address=address, status=status, status_message=status_message)
    send_all(source_conn, response_headers.encode())
    logi("Connection closed", address=address)

  def serve_status_page(self, source_conn, address):
    start_time = datetime.utcfromtimestamp(
        self.start_time/1000).strftime("%d.%m.%Y %H:%M:%S")
    response_body = status_page_template.substitute({
      "number_of_requests": str(self.number_of_requests),
      "start_date": start_time})
    response_headers = response_headers_template.substitute({
      "status_code": "200", 
      "status_message":"OK",
      "content_type":"TEXT/HTML",
      "content_length": str(len(response_body))})
    logd("serving status page", headers=response_headers, body=response_body)
    send_all(source_conn, response_headers.encode())
    send_all(source_conn, response_body.encode())
    source_conn.close()
    logi("Connection closed", address=address)

  def process_proxy_request(
          self, source_conn, address, parser, request_headers_bytes, leftover):
    destination = parser.get_headers()["host"]
    if not self.async_mode:
      self.lock.acquire()
      self.number_of_requests += 1
      self.lock.release()
    else:
      self.number_of_requests += 1
    # Connect to destination host
    logd("request", bytes=request_headers_bytes)
    dest_conn = socket.socket()
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
    if self.async_mode:
      g = gevent.spawn(self.destination_response_processing,
          source_conn, dest_conn, address, destination)
    else:
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
        source_conn.close()

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
    current_time_in_seconds = int(get_utc()/1000)
    crypto_id = str(uuid.uuid4())
    date_today = date.today().strftime("%d.%m.%Y")
    payload_data = {"user": "username",
                    "date": date_today}
    logi("generating Json web token ...",
        iat=current_time_in_seconds, jti=crypto_id, date=date_today)
    token_payload = {"iat": current_time_in_seconds,
        "jti": crypto_id, "payload": payload_data}
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
      '--async_mode', help="0 - off(use threads instead), 1 - on, default 1(on) ", default=1, type=int)
  parser.add_argument(
      '--log_dir', help="Path to the directory where the log files will be created, default ./log", default="./log", type=str)
  parser.add_argument(
      '--log_level', help="0 - DEBUG, 1 - INFO, 2 - WARN, 3 - ERROR, 4 FATAL , default INFO(1)", default=0, type=int)
  args = parser.parse_args()
  max_connection = args.max_conn
  buffer_size = args.buffer_size
  listening_port = args.http_port
  log_dir= args.log_dir
  log_level = args.log_level
  async_mode = args.async_mode

  server = ProxyServer(listening_port, buffer_size, max_connection, log_dir, log_level, async_mode)
  server.accept_new_connections()
