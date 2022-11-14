# proxy server

Simple proxy server for HTTP, HTTPS will not work. Run server_ip:port/status to see status page, number of proxy requests processed and server start time.

## Run

* Bare Metal

  ```
  python3 src/server.py
  ```

* Makefile

  Build the image first, need to execute only once.
  ```
  make build
  ```
  Run the server
  ```
  make run
  ```
  Run integration tests
  ```
  make test
  ```

## Screenshot
<p align = "left">
<img src= "assets/screenshot.png" alt ="screenshot" width="65%" height= "65%">
</p>

## Setup and Testing
If running the proxy on your local machine with the above example, point your proxy to;
```localhost 8000```

Test access to a HTTP only webpage such as;
```http://neverssl.com``` <br>
and <br>
```http://postman-echo.com```

### Example:
```curl -X GET 'http://postman-echo.com/get?foo1=bar1&foo2=bar2' -x localhost:8000```