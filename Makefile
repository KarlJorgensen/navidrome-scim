#!/usr/bin/make -f

.PHONY: run
run :
	./bin/navidrome-scim run --host 0.0.0.0

.PHONY: debug
debug :
	./bin/navidrome-scim run --host 0.0.0.0 --debug
