.PHONY: help serve demo test catalog clean

PY ?= python3
PORT ?= 8080

help:
	@echo "CyberRange control plane"
	@echo "  make serve [PORT=8080]  - run dashboard + API"
	@echo "  make demo               - end-to-end exercise in memory"
	@echo "  make test               - run the test suite"
	@echo "  make catalog            - print seeded content summary"
	@echo "  make clean              - remove runtime db + caches"

serve:
	cd backend && $(PY) -m cyberrange serve --port $(PORT)

demo:
	cd backend && $(PY) -m cyberrange demo

test:
	cd backend && $(PY) -m unittest discover -s tests -v

catalog:
	cd backend && $(PY) -m cyberrange catalog

clean:
	rm -rf backend/data/*.db backend/data/*.db-* backend/data/*.sqlite3
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
