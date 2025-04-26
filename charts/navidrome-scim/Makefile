#!/usr/bin/make -f

HELM_REPO=home
KUBE_CONTEXT=home
NAMESPACE=kj

OPTIONS = --set image.pullPolicy=Always

.PHONY: diff
diff :
	helm --kube-context $(KUBE_CONTEXT) --namespace $(NAMESPACE) diff upgrade --install $(OPTIONS) navidrome-scim .

.PHONY: upgrade
upgrade : diff
	helm --kube-context $(KUBE_CONTEXT) --namespace $(NAMESPACE) upgrade --install $(OPTIONS) navidrome-scim .

.PHONY: push
push: upgrade
	helm cm-push . home
