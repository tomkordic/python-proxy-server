FROM python:3.8

RUN mkdir /app

WORKDIR /app

RUN mkdir /app/tests

RUN mkdir /app/src

COPY requirements.txt .

EXPOSE 8000

RUN pip install -r requirements.txt

COPY src/ ./src

COPY tests/ ./tests

CMD [ "python", "./src/server.py", "--http_port=8000", "--max_conn=10", "--buffer_size=8192" ]