.PHONY: build binaries check test integration-test

build:
	docker build -t whazza .

binaries:
	pyinstaller -F bin/checker
	pyinstaller -F bin/server
	pyinstaller -F bin/client

check:
	python -m mypy --silent-imports --strict-optional whazza

test:
	python -m unittest discover

integration-test: build
	docker run --rm -it whazza bash -c "cd integration_test; ./test.sh"
