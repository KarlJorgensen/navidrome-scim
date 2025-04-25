#!/usr/bin/make -f

IMAGE=navidrome-scim
VERSION=$(shell ../setup.py --version)


.PHONY: image
image: dist/navidrome_scim.wheel
	: IMAGE=$(IMAGE)
	: VERSION=$(VERSION)
	mkdir -p dist
	cp --archive --reflink=auto ../dist/navidrome_sim-$(VERSION)-py3-none-any.wheel dist/
	docker build --tag=$(IMAGE):$(VERSION) .

dist/navidrome_scim.wheel :
	mkdir -p dist
	cp --archive --reflink=auto ../dist/navidrome_sim-$(VERSION)-py3-none-any.wheel $@

