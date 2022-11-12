FROM python:3.8

RUN mkdir /app

WORKDIR /app

COPY requirements.txt .

EXPOSE 8000

RUN pip install -r requirements.txt

COPY src/ .

CMD [ "python", "./server.py", "--http_port=8000", "--max_conn=10", "--buffer_size=8192" ]