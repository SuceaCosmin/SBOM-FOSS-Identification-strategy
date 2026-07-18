# Build environment for the SCANOSS self-mining stack: ldb (storage + shell),
# minr (miner/importer), engine (the `scanoss` matcher CLI). All three are
# GPL-2.0 — they run only inside this container as separate processes, which is
# exactly the process-boundary integration pattern the generator will need.
FROM debian:bookworm

# unrar-free: minr hard-checks for /usr/bin/unrar at startup (non-free unrar
# isn't in Debian main); the free variant provides that path via alternatives
# and we never mine .rar archives anyway.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git ca-certificates curl wget unzip p7zip-full \
    zlib1g-dev libgcrypt20-dev libssl-dev pkg-config \
    ruby xz-utils gzip tar bzip2 jq unrar-free \
    && rm -rf /var/lib/apt/lists/*

# Pin via ARG so the README can record exactly what was built.
ARG LDB_REF=master
ARG MINR_REF=master
ARG ENGINE_REF=main

# The ldb/minr Makefiles run `chown $SUDO_USER ...` in their install targets,
# assuming an interactive sudo build; inside Docker SUDO_USER is unset and
# chown fails with "missing operand". Root is the build user here anyway.
ENV SUDO_USER=root

RUN git clone https://github.com/scanoss/ldb.git /opt/ldb \
 && cd /opt/ldb && git checkout "$LDB_REF" \
 && make && make install && ldconfig

RUN git clone https://github.com/scanoss/minr.git /opt/minr \
 && cd /opt/minr && git checkout "$MINR_REF" \
 && make && make install

RUN git clone https://github.com/scanoss/engine.git /opt/engine \
 && cd /opt/engine && git checkout "$ENGINE_REF" \
 && make && make install && ldconfig

RUN mkdir -p /var/lib/ldb
WORKDIR /work
