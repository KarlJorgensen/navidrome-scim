#!/usr/bin/make -f

KUBE_CONTEXT=home
NAMESPACE=kj

OPTIONS = --set navidrome.data_pvc=navidrome-data --set image.pullPolicy=Always

.PHONY: diff
diff :
	helm --kube-context $(KUBE_CONTEXT) --namespace $(NAMESPACE) diff upgrade --install $(OPTIONS) navidrome-scim .

.PHONY: upgrade
upgrade : diff
	helm --kube-context $(KUBE_CONTEXT) --namespace $(NAMESPACE) upgrade --install $(OPTIONS) navidrome-scim .
