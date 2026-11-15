PY ?= python

.PHONY: demo data review test clean

demo: data review

data:
	$(PY) src/generate_data.py --employees 400 --seed 42 --ref-date 2026-11-13

review:
	$(PY) src/run_review.py

test:
	$(PY) -m unittest discover -s tests -v

clean:
	rm -rf output
