TAG:=$(shell git describe --tags --always | sed 's/^v//')
DOCKER?=docker

.PHONY=image
image:
	$(DOCKER) build \
		--build-arg VERSION=$(TAG) \
		-t suricata_exporter:$(TAG) \
		-t suricata_exporter:latest \
		.
