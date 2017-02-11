.PHONY: build run integration-test

build:
	docker build -t whazza .

run-checker:
	docker run --rm -it -v $(PWD)/checker:/app -v $(PWD):/data --link whazzaserver whazza python3 checker.py

run-server:
	docker run --rm -it --name whazzaserver -v $(PWD)/server:/app -p 5555:5555  whazza python3 server.py

run-client:
	docker run --rm -it -v $(PWD)/client:/app --link whazzaserver whazza python3 client.py

integration-test:
	docker run --rm -it whazza bash -c "cd integration_test; ./test.sh"
