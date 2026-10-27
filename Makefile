.PHONY: install test lint clean run dashboard docker

install:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest tests/ -v

lint:
	ruff check redscout/

clean:
	rm -rf __pycache__ .pytest_cache build dist *.egg-info
	rm -f report.pdf report.html audit.log

run:
	python -m redscout.main -s scopes/example_scope.yaml -t 127.0.0.1

dashboard:
	python -m redscout.main dashboard

docker:
	docker compose -f docker/docker-compose.yml up --build