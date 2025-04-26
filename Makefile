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

.PHONY: image-push
image-push: image
	$(MAKE) -C docker push


.PHONY: helm-diff
helm-diff :
	$(MAKE) -C charts/navidrome-scim diff

.PHONY: helm-upgrade
helm-upgrade: image-push
	$(MAKE) -C charts/navidrome-scim upgrade
