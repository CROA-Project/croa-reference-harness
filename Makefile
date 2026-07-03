.PHONY: demo test
demo:
	python3 -m mrh
test:
	python3 -m unittest discover -s tests -v
