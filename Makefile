build:
	docker build -t proxy-server .

run:
	docker run --rm -p 8000:8000 --name proxy  proxy-server

test:
	docker-compose up --abort-on-container-exit