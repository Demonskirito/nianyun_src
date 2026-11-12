# Control-plane image: console, API, bounded blackbox tools and persistent data.
# It intentionally contains no VPN, ARL services or CTF runtime entrypoint.
#
# Build stages (only their outputs reach `control`):
#   blackbox-tools  pinned ProjectDiscovery release binaries, sha256-verified
#   build           Node/TS compile of the API + console, dev deps pruned
#   tools           Go/Python tool artifacts; the whole stage is DISCARDED
#   control         Node runtime + copied binaries/venvs/source trees only
#
# Network discipline (verified on Docker Desktop behind a host proxy):
#   * The build container has NO direct outbound route. Every direct connection
#     (deb.debian.org, mirrors.aliyun.com, github.com) times out. Keep the proxy
#     injected by --build-arg HTTP_PROXY/HTTPS_PROXY in ALL RUN instructions.
#   * node:*-bookworm-slim has no /etc/ssl/certs/ca-certificates.crt, so apt
#     cannot validate any HTTPS mirror. Seed it from Node's bundled root CAs
#     BEFORE the first apt-get update.
#   * Defaults below are upstream sources so this file also builds on CI. On a
#     proxied desktop, override APT_MIRROR, PIP_INDEX_URL, GO_DOWNLOAD_URL,
#     GOPROXY and PLAYWRIGHT_DOWNLOAD_HOST with build-args for reachable mirrors.
#   * If the host proxy has no working overseas exit, set GITHUB_PROXY_PREFIX
#     to a GitHub mirror (e.g. https://gh-proxy.com/). Release assets are still
#     verified against their pinned sha256, so a tampered mirror cannot pass.
# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE=node:22.22.0-bookworm-slim

# ── Stage: pinned ProjectDiscovery release binaries ─────────────────────────
FROM ${NODE_IMAGE} AS blackbox-tools
ARG APT_MIRROR=http://deb.debian.org
ARG GITHUB_PROXY_PREFIX=
ARG HTTPX_VERSION=1.12.0
ARG HTTPX_SHA256=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
ARG KATANA_VERSION=1.7.0
ARG KATANA_SHA256=fe1142d92f418549338ea46d67a472124878482e225d279e9a42700c75d76a4d
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG SUBFINDER_VERSION=2.16.0
ARG SUBFINDER_SHA256=1b7f9c608e9a5bd59e609a5e09710d63c5485e92d3d49dc2c16eb4fdbe10cb60
ARG DNSX_VERSION=1.2.2
ARG DNSX_SHA256=dabd54146d63b53fdd08186156ca117fcb79656c66153e3d3c61367aa87a9943
ARG NAABU_VERSION=2.6.1
ARG NAABU_SHA256=018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90
ARG GAU_VERSION=2.2.4
ARG GAU_SHA256=10e2e248c37cafb0be3f6d2931125296b95cd4186066d596d47fa417237529a9
ARG FFUF_VERSION=2.1.0
ARG FFUF_SHA256=fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5
WORKDIR /opt/nianyun
RUN set -eux; \
    mkdir -p /etc/ssl/certs; \
    node -e "require('fs').writeFileSync('/etc/ssl/certs/ca-certificates.crt', require('tls').rootCertificates.join('\n') + '\n')"; \
    sed -i "s|http://deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    printf 'Acquire::Retries "5";\n' > /etc/apt/apt.conf.d/80-nianyun-apt; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    rm -rf /var/lib/apt/lists/*
# Outputs go to a dedicated directory: copying the whole /usr/local/bin from a
# Node-based stage would also copy (and duplicate) node/npm/npx into the runtime.
# The cache mount keeps already verified assets across failed builds, so a
# transient TLS reset on one download does not re-fetch the other seven.
RUN --mount=type=cache,id=nianyun-assets,target=/opt/assets-cache \
    set -eux; \
    mkdir -p /opt/tool-bin /opt/assets-cache; \
    for spec in \
      "httpx|${GITHUB_PROXY_PREFIX}https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip|${HTTPX_SHA256}" \
      "katana|${GITHUB_PROXY_PREFIX}https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip|${KATANA_SHA256}" \
      "nuclei|${GITHUB_PROXY_PREFIX}https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip|${NUCLEI_SHA256}" \
      "subfinder|${GITHUB_PROXY_PREFIX}https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip|${SUBFINDER_SHA256}" \
      "dnsx|${GITHUB_PROXY_PREFIX}https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip|${DNSX_SHA256}" \
      "naabu|${GITHUB_PROXY_PREFIX}https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip|${NAABU_SHA256}"; do \
      name="${spec%%|*}"; rest="${spec#*|}"; url="${rest%%|*}"; sha="${rest##*|}"; \
      f="/opt/assets-cache/${name}.zip"; \
      if ! echo "$sha  $f" | sha256sum -c - >/dev/null 2>&1; then \
        curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors --connect-timeout 20 "$url" -o "$f"; \
      fi; \
      echo "$sha  $f" | sha256sum -c -; \
      unzip -p "$f" "$name" > "/opt/tool-bin/${name}"; \
      chmod 0755 "/opt/tool-bin/${name}"; \
    done; \
    for spec in \
      "gau|${GITHUB_PROXY_PREFIX}https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_amd64.tar.gz|${GAU_SHA256}" \
      "ffuf|${GITHUB_PROXY_PREFIX}https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz|${FFUF_SHA256}"; do \
      name="${spec%%|*}"; rest="${spec#*|}"; url="${rest%%|*}"; sha="${rest##*|}"; \
      f="/opt/assets-cache/${name}.tar.gz"; \
      if ! echo "$sha  $f" | sha256sum -c - >/dev/null 2>&1; then \
        curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors --connect-timeout 20 "$url" -o "$f"; \
      fi; \
      echo "$sha  $f" | sha256sum -c -; \
      tar -xOzf "$f" "$name" > "/opt/tool-bin/${name}"; \
      chmod 0755 "/opt/tool-bin/${name}"; \
    done

# ── Stage: Node/TS build of the console + API ───────────────────────────────
FROM ${NODE_IMAGE} AS build
WORKDIR /opt/nianyun
COPY package.json package-lock.json ./
COPY console/package.json console/package-lock.json ./console/
RUN --mount=type=cache,id=nianyun-npm,target=/root/.npm,sharing=locked \
    npm ci && npm --prefix console ci
COPY tsconfig.json ./
COPY src/ ./src/
COPY bin/ ./bin/
COPY scripts/ ./scripts/
COPY resources/ ./resources/
COPY deploy/unified/ ./deploy/unified/
COPY console/ ./console/
COPY tools.env.example.yaml ./
RUN npm run build && npm prune --omit=dev \
 && rm -rf src console/src console/node_modules /root/.npm

# ── Stage: toolchain builder (discarded) ────────────────────────────────────
# Go toolchain, gcc and git live ONLY here. The final image receives the compiled
# binaries, the two venvs and the three source trees — never a compiler.
FROM ${NODE_IMAGE} AS tools
ARG APT_MIRROR=http://deb.debian.org
ARG GITHUB_PROXY_PREFIX=
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG GOPROXY=https://goproxy.cn,direct
# Go 1.25.10: dalfox v2.13.0 requires go >= 1.25.5 and trufflehog v3.99.2
# declares toolchain go1.25.10. With Go 1.24.6 + GOTOOLCHAIN=auto the builder
# silently downloaded a second ~58MB toolchain through the proxy.
ARG GO_VERSION=1.25.10
ARG GO_SHA256=42d4f7a32316aa66591eca7e89867256057a4264451aca10570a715b3637ba70
ARG GO_DOWNLOAD_URL=https://mirrors.aliyun.com/golang
ARG INTERACTSH_VERSION=v1.2.2
ARG DALFOX_VERSION=v2.13.0
ARG SUBJS_VERSION=v1.0.0
ARG KITERUNNER_VERSION=v1.0.2
ARG TESTSSL_VERSION=v3.2.3
ARG JWT_TOOL_VERSION=v2.3.0
ARG TRUFFLEHOG_VERSION=v3.99.2
# graphql-cop has no tagged release; pin an exact commit for reproducibility.
ARG GRAPHQLCOP_COMMIT=2b7e086efae672f28b419c7fcdfe6b48d846c9dc
WORKDIR /opt/nianyun
RUN set -eux; \
    mkdir -p /etc/ssl/certs; \
    node -e "require('fs').writeFileSync('/etc/ssl/certs/ca-certificates.crt', require('tls').rootCertificates.join('\n') + '\n')"; \
    sed -i "s|http://deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    printf 'Acquire::Retries "5";\n' > /etc/apt/apt.conf.d/80-nianyun-apt; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 python3-venv python3-dev gcc; \
    rm -rf /var/lib/apt/lists/*
# gcc + python3-dev are kept on purpose: graphql-cop pins simplejson==3.17.6,
# which has no cp311 wheel and must be built from its sdist. Everything else
# removed from the old layer was dead weight (build-essential's g++/make/dpkg-dev,
# system python3-pip, wget — curl handles every download).
RUN set -eux; \
    curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors \
      "${GO_DOWNLOAD_URL}/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz; \
    echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm -f /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:$PATH
# Pinned source snapshots as tarballs (GitHub, optionally mirrored). Tarballs
# avoid the git smart-HTTP protocol, which public GitHub mirrors do not relay.
RUN set -eux; \
    mkdir -p /opt/nianyun/testssl.sh /opt/nianyun/jwt_tool /opt/nianyun/graphql-cop; \
    curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
      "${GITHUB_PROXY_PREFIX}https://github.com/testssl/testssl.sh/archive/refs/tags/${TESTSSL_VERSION}.tar.gz" -o /tmp/testssl.tar.gz; \
    tar -xzf /tmp/testssl.tar.gz -C /opt/nianyun/testssl.sh --strip-components=1; \
    curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
      "${GITHUB_PROXY_PREFIX}https://github.com/ticarpi/jwt_tool/archive/refs/tags/${JWT_TOOL_VERSION}.tar.gz" -o /tmp/jwt_tool.tar.gz; \
    tar -xzf /tmp/jwt_tool.tar.gz -C /opt/nianyun/jwt_tool --strip-components=1; \
    curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
      "${GITHUB_PROXY_PREFIX}https://github.com/dolevf/graphql-cop/archive/${GRAPHQLCOP_COMMIT}.tar.gz" -o /tmp/graphql-cop.tar.gz; \
    tar -xzf /tmp/graphql-cop.tar.gz -C /opt/nianyun/graphql-cop --strip-components=1; \
    rm -f /tmp/*.tar.gz
# Go tools: module downloads go through GOPROXY (proxied when a proxy is set).
# GOTOOLCHAIN=local keeps the build on the pinned Go above instead of fetching
# a second toolchain.
# trufflehog cannot use `go install module@version`: its go.mod contains replace
# directives, which Go rejects for a non-main module. Build the pinned source
# archive as a main module instead.
RUN --mount=type=cache,id=nianyun-go-mod,target=/root/go/pkg/mod,sharing=locked \
 --mount=type=cache,id=nianyun-go-build,target=/root/.cache/go-build,sharing=locked \
    set -eux; \
    export PATH=/usr/local/go/bin:$PATH \
      CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=${GOPROXY}; \
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION}; \
    go install github.com/hahwul/dalfox/v2@${DALFOX_VERSION}; \
    go install github.com/lc/subjs@${SUBJS_VERSION}; \
    go install github.com/assetnote/kiterunner/cmd/kiterunner@${KITERUNNER_VERSION}; \
    mkdir -p /tmp/trufflehog-src /root/go/bin; \
    curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
      "${GITHUB_PROXY_PREFIX}https://github.com/trufflesecurity/trufflehog/archive/refs/tags/${TRUFFLEHOG_VERSION}.tar.gz" -o /tmp/trufflehog.tar.gz; \
    tar -xzf /tmp/trufflehog.tar.gz -C /tmp/trufflehog-src --strip-components=1; \
    (cd /tmp/trufflehog-src && go build -o /root/go/bin/trufflehog .); \
    rm -rf /tmp/trufflehog-src /tmp/trufflehog.tar.gz
# Python venvs: arjun/semgrep + jwt_tool deps share one, graphql-cop has its own
# (its requests==2.25.1 conflicts with semgrep's newer requests).
RUN set -eux; \
    python3 -m venv /opt/nianyun/tool-venv; \
    python3 -m venv /opt/nianyun/graphql-venv; \
    export PIP_INDEX_URL=${PIP_INDEX_URL} PIP_NO_CACHE_DIR=1 \
      PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=5; \
    /opt/nianyun/tool-venv/bin/pip install arjun semgrep; \
    /opt/nianyun/tool-venv/bin/pip install -r /opt/nianyun/jwt_tool/requirements.txt; \
    /opt/nianyun/graphql-venv/bin/pip install -r /opt/nianyun/graphql-cop/requirements.txt
# Collect only the artifacts the runtime needs into one directory.
RUN set -eux; \
    mkdir -p /opt/nianyun/tool-bin; \
    cp /root/go/bin/interactsh-client /opt/nianyun/tool-bin/interactsh-client; \
    cp /root/go/bin/dalfox /opt/nianyun/tool-bin/dalfox; \
    cp /root/go/bin/subjs /opt/nianyun/tool-bin/subjs; \
    cp /root/go/bin/kiterunner /opt/nianyun/tool-bin/kiterunner; \
    if [ -f /root/go/bin/trufflehog ]; then cp /root/go/bin/trufflehog /opt/nianyun/tool-bin/trufflehog; \
    elif [ -f /root/go/bin/v3 ]; then cp /root/go/bin/v3 /opt/nianyun/tool-bin/trufflehog; \
    else echo "trufflehog binary was not produced" >&2; exit 1; fi; \
    ln -s /opt/nianyun/tool-venv/bin/arjun /opt/nianyun/tool-bin/arjun; \
    ln -s /opt/nianyun/tool-venv/bin/semgrep /opt/nianyun/tool-bin/semgrep; \
    ln -s /opt/nianyun/testssl.sh/testssl.sh /opt/nianyun/tool-bin/testssl.sh; \
    printf '#!/bin/sh\nexec /opt/nianyun/tool-venv/bin/python /opt/nianyun/jwt_tool/jwt_tool.py "$@"\n' > /opt/nianyun/tool-bin/jwt_tool; \
    printf '#!/bin/sh\nexec /opt/nianyun/graphql-venv/bin/python /opt/nianyun/graphql-cop/graphql-cop.py "$@"\n' > /opt/nianyun/tool-bin/graphql-cop; \
    chmod 0755 /opt/nianyun/tool-bin/jwt_tool /opt/nianyun/tool-bin/graphql-cop

# ── Stage: final runtime image ──────────────────────────────────────────────
FROM ${NODE_IMAGE} AS control
ARG APT_MIRROR=http://deb.debian.org
# Playwright browsers come from a domestic mirror too; the default CDN is only
# reachable through the (slow) proxy on this network. Override with a build-arg
# when building from a network where the official CDN is faster.
ARG PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.npmmirror.com/binaries/playwright
WORKDIR /opt/nianyun
ENV NODE_ENV=production \
    NIANYUN_REPO_ROOT=/opt/nianyun \
    KATANA_PATH=/usr/local/bin/katana \
    HTTPX_PATH=/usr/local/bin/httpx \
    NUCLEI_PATH=/usr/local/bin/nuclei \
    SUBFINDER_PATH=/usr/local/bin/subfinder \
    DNSX_PATH=/usr/local/bin/dnsx \
    NAABU_PATH=/usr/local/bin/naabu \
    GAU_PATH=/usr/local/bin/gau \
    FFUF_PATH=/usr/local/bin/ffuf \
    INTERACTSH_CLIENT_PATH=/usr/local/bin/interactsh-client \
    ARJUN_PATH=/usr/local/bin/arjun \
    SUBJS_PATH=/usr/local/bin/subjs \
    TESTSSL_PATH=/usr/local/bin/testssl.sh \
    KITERUNNER_PATH=/usr/local/bin/kiterunner \
    DALFOX_PATH=/usr/local/bin/dalfox \
    SQLMAP_PATH=/usr/local/bin/sqlmap \
    JWT_TOOL_PATH=/usr/local/bin/jwt_tool \
    GRAPHQL_COP_PATH=/usr/local/bin/graphql-cop \
    WPSCAN_PATH=/usr/local/bin/wpscan \
    TRUFFLEHOG_PATH=/usr/local/bin/trufflehog \
    SEMGREP_PATH=/usr/local/bin/semgrep \
    PATH=/opt/nianyun/bin:/opt/nianyun/node_modules/.bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
# Runtime packages. ruby-dev/build-essential exist only to compile wpscan's
# native gems and are purged inside this same layer, so they never ship.
RUN set -eux; \
    mkdir -p /etc/ssl/certs; \
    node -e "require('fs').writeFileSync('/etc/ssl/certs/ca-certificates.crt', require('tls').rootCertificates.join('\n') + '\n')"; \
    sed -i "s|http://deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    printf 'Acquire::Retries "5";\n' > /etc/apt/apt.conf.d/80-nianyun-apt; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl openssl libcurl4 bsdextrautils procps \
      python3 ruby ruby-dev build-essential sqlmap; \
    rm -rf /var/lib/apt/lists/*
# Tool artifacts (no toolchain, no /root/go/bin, no second copy of node/npm).
COPY --from=blackbox-tools /opt/tool-bin/ /usr/local/bin/
COPY --from=tools /opt/nianyun/tool-bin/ /usr/local/bin/
COPY --from=tools /opt/nianyun/tool-venv /opt/nianyun/tool-venv
COPY --from=tools /opt/nianyun/graphql-venv /opt/nianyun/graphql-venv
COPY --from=tools /opt/nianyun/jwt_tool /opt/nianyun/jwt_tool
COPY --from=tools /opt/nianyun/graphql-cop /opt/nianyun/graphql-cop
COPY --from=tools /opt/nianyun/testssl.sh /opt/nianyun/testssl.sh
# Application.
COPY --from=build /opt/nianyun/ /opt/nianyun/
COPY deploy/control/config.yaml /opt/nianyun/deploy/control/config.yaml
COPY deploy/control/entrypoint.sh /usr/local/bin/nianyun-control
RUN set -eux; \
    export PLAYWRIGHT_DOWNLOAD_HOST=${PLAYWRIGHT_DOWNLOAD_HOST}; \
    /opt/nianyun/node_modules/.bin/playwright install-deps chromium; \
    /opt/nianyun/node_modules/.bin/playwright install chromium; \
    gem install --no-document wpscan; \
    apt-get purge -y --auto-remove ruby-dev build-essential; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    ln -sf /usr/bin/sqlmap /usr/local/bin/sqlmap; \
    sed -i 's/\r$//' /usr/local/bin/nianyun-control; \
    find /opt/nianyun/bin -type f -exec sed -i 's/\r$//' {} +; \
    find /opt/nianyun/deploy/unified -type f -name '*.sh' -exec sed -i 's/\r$//' {} +; \
    chmod 0755 /usr/local/bin/nianyun-control /opt/nianyun/bin/*; \
    mkdir -p /opt/nianyun/data/config
EXPOSE 8700
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8700/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/local/bin/nianyun-control"]
