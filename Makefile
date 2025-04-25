#!/usr/bin/make -f

.PHONY: run
run : wheel
	$(MAKE) -C docker run

.PHONY: debug
debug : wheel
	$(MAKE) -C docker debug

.PHONY: wheel
wheel:
	./setup.py bdist_wheel

.PHONY: image
image: wheel
	$(MAKE) -C docker image
