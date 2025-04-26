#!/usr/bin/make -f

.PHONY: run-local
# Assumes you have a python venv with the package installed,
# and have set up port forwarding to the navidrome service
run-local:
	. ./bin/activate ; NAVIDROME_BASE_URL=http://localhost:4533 USERNAME=akadmin navidrome-scim run --host 0.0.0.0

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
