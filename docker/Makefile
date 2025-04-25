#!/usr/bin/make -f

IMAGE=navidrome-scim
VERSION=$(shell ../setup.py --version)

WHEEL = navidrome_scim-$(VERSION)-py3-none-any.whl

.PHONY: image
image: dist/$(WHEEL)
	: IMAGE=$(IMAGE)
	: VERSION=$(VERSION)
	docker build --tag=$(IMAGE):$(VERSION) --build-arg=WHEEL=$(WHEEL) .

dist/$(WHEEL) :
	mkdir -p dist
	-rm -f dist/*
	cp --archive --reflink=auto ../dist/$(WHEEL) $@

.PHONY: run
run: image
	docker run --interactive --rm --publish 0.0.0.0:5000:5000 $(IMAGE):$(VERSION) run
