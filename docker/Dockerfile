
FROM debian:bookworm-slim

RUN DEBIAN_FRONTEND=noninteractive; \
    apt-get update --quiet  && \
    apt-get install --no-install-recommends --quiet --assume-yes python3 

RUN DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --assume-yes pipx

# Set up a user - the uid/guid matches the one use in the navidrome docker image
RUN groupadd --gid 568 navidrome
RUN useradd --uid 568 --gid navidrome --create-home navidrome

EXPOSE 5000
COPY entrypoint /home/navidrome/entrypoint
ENTRYPOINT [ "/home/navidrome/entrypoint" ]

ARG WHEEL
RUN echo Wheel is ${WHEEL}
COPY dist/${WHEEL} /tmp/${WHEEL}

USER navidrome
RUN PIPX_BIN_DIR=/home/navidrome/bin pipx install --include-deps --verbose --system-site-packages /tmp/${WHEEL}
# &&  rm -f /tmp/${WHEEL}

