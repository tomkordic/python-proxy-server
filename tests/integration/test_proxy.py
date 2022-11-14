import unittest
import socket
from os import environ
from datetime import date
from requests import get, post
from requests.exceptions import ConnectionError
import jwt
from src.utils import get_utc, logi, logd, setup_logging, is_valid_ip_address, LOG_LEVEL_INFO
from src.constants import JWT_SECRET

setup_logging(LOG_LEVEL_INFO, None, None)

proxy_host = "127.0.0.1"
if environ.get('proxy_host') is not None:
  proxy_host = environ.get('proxy_host')
  if not is_valid_ip_address(proxy_host):
    ## must be a domain
    proxy_host = socket.gethostbyname(proxy_host)
  
proxy_port = "8000"
if environ.get('proxy_port') is not None:
  proxy_port = environ.get('proxy_port')

logi("Looking for proxy server on", host=proxy_host, port=proxy_port)

class ProxyTest(unittest.TestCase):
  def setUp(self):
    pass

  def test_proxy_and_jwt(self):
    logi("test_proxy_and_jwt")
    proxies = {
        'http': "http://" + proxy_host + ":" + proxy_port,
    }
    url = 'http://postman-echo.com/post'
    time_in_seconds_when_sent = int(get_utc()/1000)
    response = post(url, proxies=proxies)
    if response.status_code != 200:
      self.fail("Proxy request failed with status code: " + response.status_code)
    headers = response.json()["headers"]
    jwt_encoded = headers["x-my-jwt"]
    logd("x-my-jwt", value=jwt_encoded)
    ## decode JWT
    token = jwt.decode(jwt_encoded, key=JWT_SECRET, algorithms=['HS512'])
    iat = int(token["iat"])
    if (abs(time_in_seconds_when_sent - iat) > 3):
      self.fail("JWT timestamp do not reflect the time of JWT generation, request time: " 
                + time_in_seconds_when_sent + ", iat: " + iat + ", diff: " 
                + str(abs(time_in_seconds_when_sent - iat)))
    received_payload = token["payload"]
    if received_payload["user"] != "username":
      self.fail("JWT payload value for user is incorrect, received: " 
        + received_payload["user"] + ", expected: username")
    if received_payload["date"] != date.today().strftime("%d.%m.%Y"):
      self.fail("JWT payload value for date do not match todays date, received: "
                + received_payload["date"] + ", expected: " 
                + date.today().strftime("%d.%m.%Y"))
  
  def test_status_page(self):
    logi("test_status_page")

    request = get("http://" + proxy_host + ":" + proxy_port + "/status")
    status_page = request.content.decode('utf8')
    if request.status_code != 200:
      self.fail("Got bad response status code: " + str(request.status_code))
    if status_page.find("<p><b>Number of requests:</b>") == -1:
      self.fail("Missing status paragraph.")
    if status_page.find("<p><b>Started at:</b>") == -1:
      self.fail("Missing started paragraph.")


if __name__ == "__main__":
    unittest.main()
