#!/usr/bin/make -f

.PHONY: run-local
# Assumes you have a python venv with the package installed,
# and have set up port forwarding to the navidrome service on port 4533
run-local:
	. ./bin/activate ; \
	export NAVIDROME_BASE_URL=http://localhost:4533; \
	export USERNAME=akadmin ; \
	export USERNAME_HEADER=X-Authentik-Username; \
	export BEARER_TOKEN=GoodForDevOnly; \
		navidrome-scim run --host 0.0.0.0

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

.PHONY: chart-push
chart-push: helm-upgrade
	$(MAKE) -C charts/navidrome-scim push

.PHONY: image-push
image-push: image
	$(MAKE) -C docker push

.PHONY: push
push: image-push chart-push

.PHONY: helm-diff
helm-diff :
	$(MAKE) -C charts/navidrome-scim diff

.PHONY: helm-upgrade
helm-upgrade: image-push
	$(MAKE) -C charts/navidrome-scim upgrade
