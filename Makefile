.PHONY: demo test p4
demo:
	python3 -m mrh
test:
	python3 -m unittest discover -s tests -v
p4:
	python3 -m unittest tests.test_p4 -v
