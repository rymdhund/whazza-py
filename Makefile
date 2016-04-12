.PHONY: build run

build:
	docker build -t status2 .

run-checker:
	docker run --rm -it -v $(PWD)/checker:/app --link status2server status2 python3 checker.py

run-server:
	docker run --rm -it --name status2server -v $(PWD)/server:/app status2 python3 server.py
