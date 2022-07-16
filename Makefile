all: scr example

scr:
	./setup_env.sh

example:
	python example_test.py

clear:
	rm -f ./OUTPUT/*.txt

