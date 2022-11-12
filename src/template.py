from string import Template

response_headers_template = Template("""HTTP/1.1 $status_code $status_message\r\nServer: Proxy-server/1.0\r\nContent-Type: $content_type; charset=utf-8\r\nContent-Length: $content_length\r\n\r\n""")

status_page_template = Template("""
<!DOCTYPE html>
<html>

<head>
<meta charset="utf-8">
<title>Proxy server status</title>
</head>

<body>
  <div>
    <p><b>Number of requests:</b> $number_of_requests
    <br>
    <p><b>Started at:</b> $start_date
  </div>
</body>

</html>
""")