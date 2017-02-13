.PHONY: build check test integration-test

build:
	docker build -t whazza .

check:
	python -m mypy --silent-imports whazza

test:
	python -m unittest discover

integration-test: build
	docker run --rm -it whazza bash -c "cd integration_test; ./test.sh"
