# Control-plane image: console, API, bounded blackbox tools and persistent data.
# It intentionally contains no VPN, ARL services or CTF runtime entrypoint.
#
# Build architecture (publish-friendly):
#   blackbox-tools  prebuilt PD binaries (sha256-verified) — runtime needed
#   build           Node/TS compile of the console + API
#   tools           BUILDER stage: installs Go/Ruby/Python toolchains and compiles the
#                   heavyweight security tools. This stage is DISCARDED; only its
#                   compiled binaries / venvs are copied into the final image, so the
#                   Go toolchain, build-essential, ruby-dev and git never reach the
#                   shipped image.
#   control         final runtime image: Node + the copied tool binaries/venvs only.
# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE=node:22.22.0-bookworm-slim

# ── Stage: prebuilt blackbox CLI tools (sha256-verified) ─────────────────────
FROM ${NODE_IMAGE} AS blackbox-tools
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
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && for spec in \
      "httpx|https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip|${HTTPX_SHA256}" \
      "katana|https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip|${KATANA_SHA256}" \
      "nuclei|https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip|${NUCLEI_SHA256}" \
      "subfinder|https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip|${SUBFINDER_SHA256}" \
      "dnsx|https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip|${DNSX_SHA256}" \
      "naabu|https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip|${NAABU_SHA256}"; do \
      name="${spec%%|*}"; rest="${spec#*|}"; url="${rest%%|*}"; sha="${rest##*|}"; \
      curl -fsSL "$url" -o "/tmp/${name}.zip"; echo "$sha  /tmp/${name}.zip" | sha256sum -c -; \
      unzip -p "/tmp/${name}.zip" "$name" > "/usr/local/bin/${name}"; chmod 0755 "/usr/local/bin/${name}"; \
    done \
 && for spec in \
      "gau|https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_amd64.tar.gz|${GAU_SHA256}" \
      "ffuf|https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz|${FFUF_SHA256}"; do \
      name="${spec%%|*}"; rest="${spec#*|}"; url="${rest%%|*}"; sha="${rest##*|}"; \
      curl -fsSL "$url" -o "/tmp/${name}.tar.gz"; echo "$sha  /tmp/${name}.tar.gz" | sha256sum -c -; \
      tar -xOzf "/tmp/${name}.tar.gz" "$name" > "/usr/local/bin/${name}"; chmod 0755 "/usr/local/bin/${name}"; \
    done \
 && rm -f /tmp/*.zip /tmp/*.tar.gz \
 && for name in httpx katana nuclei subfinder dnsx naabu gau ffuf; do "/usr/local/bin/$name" -version >/dev/null 2>&1 || true; done

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

# ── Stage: toolchain builder for the heavyweight security tools ──────────────
# Everything that needs Go / Ruby-dev / build-essential / git to BUILD lives here.
# This whole stage is discarded; only its outputs are copied into `control`.
FROM ${NODE_IMAGE} AS tools
ARG GO_VERSION=1.24.6
ARG GO_SHA256=bbca37cc395c974ffa4893ee35819ad23ebb27426df87af92e93a9ec66ef8712
ARG INTERACTSH_VERSION=v1.2.2
ARG DALFOX_VERSION=v2.13.0
ARG SUBJS_VERSION=v1.0.0
ARG KITERUNNER_VERSION=v1.0.2
ARG TESTSSL_VERSION=v3.2.3
ARG JWT_TOOL_VERSION=v2.3.0
ARG TRUFFLEHOG_VERSION=v3.99.2
# graphql-cop has no tagged release; pin an exact commit for reproducibility.
ARG GRAPHQLCOP_COMMIT=2b7e086efae672f28b419c7fcdfe6b48d846c9dc
ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple
ARG PIP_DEFAULT_TIMEOUT=300
ARG PIP_RETRIES=5
ENV PIP_INDEX_URL=${PIP_INDEX_URL} \
    PIP_DEFAULT_TIMEOUT=${PIP_DEFAULT_TIMEOUT} \
    PIP_RETRIES=${PIP_RETRIES}
WORKDIR /opt/nianyun
# 与 control 阶段保持一致：把 Debian 源换到阿里云镜像并开启 apt 重试。
# 否则 tools 阶段直连 deb.debian.org（经代理约 40KB/s、35 分钟后还会在大包上 502），
# 而 control 阶段走国内镜像是快的；这是多阶段拆分时漏掉的一处。
RUN mkdir -p /etc/ssl/certs \
 && node -e "require('fs').writeFileSync('/etc/ssl/certs/ca-certificates.crt', require('tls').rootCertificates.join('\n') + '\n')" \
 && sed -i \
      -e 's|http://deb.debian.org/debian-security|https://mirrors.aliyun.com/debian-security|g' \
      -e 's|http://deb.debian.org/debian|https://mirrors.aliyun.com/debian|g' \
      /etc/apt/sources.list.d/debian.sources \
 && printf 'Acquire::Retries "5";\n' > /etc/apt/apt.conf.d/80-retries \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git \
      python3 python3-venv python3-dev python3-pip \
      build-essential \
 && rm -rf /var/lib/apt/lists/*
# Go toolchain (only used to compile the go-install tools below).
RUN wget -q https://mirrors.aliyun.com/golang/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz \
 && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
 && tar -C /usr/local -xzf /tmp/go.tar.gz \
 && rm -f /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:/root/go/bin:$PATH
# Python venvs (arjun/semgrep + graphql-cop). graphql-cop repo is pinned separately below.
RUN python3 -m venv /opt/nianyun/tool-venv \
 && /opt/nianyun/tool-venv/bin/pip install --no-cache-dir --timeout 300 --retries 5 arjun semgrep
RUN python3 -m venv /opt/nianyun/graphql-venv
# Pinned git clones (testssl / jwt_tool).
RUN git clone --depth 1 --branch ${TESTSSL_VERSION} https://github.com/testssl/testssl.sh.git /opt/nianyun/testssl.sh
RUN git clone --depth 1 --branch ${JWT_TOOL_VERSION} https://github.com/ticarpi/jwt_tool.git /opt/nianyun/jwt_tool \
 && /opt/nianyun/tool-venv/bin/pip install --no-cache-dir --timeout 300 --retries 5 -r /opt/nianyun/jwt_tool/requirements.txt
# Go-install tools (pinned versions → reproducible).
RUN --mount=type=cache,id=nianyun-go-mod,target=/root/go/pkg/mod,sharing=locked \
 --mount=type=cache,id=nianyun-go-build,target=/root/.cache/go-build,sharing=locked \
 export PATH=/usr/local/go/bin:$PATH \
 && GOTOOLCHAIN=auto go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION} \
 && GOTOOLCHAIN=auto go install github.com/hahwul/dalfox/v2@${DALFOX_VERSION} \
 && GOTOOLCHAIN=auto go install github.com/lc/subjs@${SUBJS_VERSION} \
 && GOTOOLCHAIN=auto go install github.com/assetnote/kiterunner/cmd/kiterunner@${KITERUNNER_VERSION}
# Trufflehog (pinned tag, compiled from source).
RUN --mount=type=cache,id=nianyun-go-mod,target=/root/go/pkg/mod,sharing=locked \
 --mount=type=cache,id=nianyun-go-build,target=/root/.cache/go-build,sharing=locked \
 git clone --depth 1 --branch ${TRUFFLEHOG_VERSION} https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog \
 && export PATH=/usr/local/go/bin:$PATH \
 && cd /tmp/trufflehog \
 && CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath -ldflags "-s -w" -o /usr/local/bin/trufflehog . \
 && rm -rf /tmp/trufflehog
# graphql-cop pinned commit.
RUN git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/nianyun/graphql-cop-pinned \
 && cd /opt/nianyun/graphql-cop-pinned && git fetch --depth 1 origin ${GRAPHQLCOP_COMMIT} && git checkout -q ${GRAPHQLCOP_COMMIT} \
 && /opt/nianyun/graphql-venv/bin/pip install --no-cache-dir --timeout 300 --retries 5 -r /opt/nianyun/graphql-cop-pinned/requirements.txt \
 && rm -rf /opt/nianyun/graphql-cop && mv /opt/nianyun/graphql-cop-pinned /opt/nianyun/graphql-cop
# Launcher scripts + symlinks so the final stage only consumes outputs.
RUN ln -sf /root/go/bin/interactsh-client /usr/local/bin/interactsh-client \
 && ln -sf /root/go/bin/dalfox /usr/local/bin/dalfox \
 && ln -sf /root/go/bin/subjs /usr/local/bin/subjs \
 && ln -sf /root/go/bin/kiterunner /usr/local/bin/kiterunner \
 && ln -sf /opt/nianyun/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
 && printf '#!/bin/sh\nexec /opt/nianyun/tool-venv/bin/python /opt/nianyun/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
 && printf '#!/bin/sh\nexec /opt/nianyun/graphql-venv/bin/python /opt/nianyun/graphql-cop/graphql-cop.py "$@"\n' > /usr/local/bin/graphql-cop \
 && chmod 0755 /usr/local/bin/jwt_tool /usr/local/bin/graphql-cop \
 && ln -sf /opt/nianyun/tool-venv/bin/arjun /usr/local/bin/arjun \
 && ln -sf /opt/nianyun/tool-venv/bin/semgrep /usr/local/bin/semgrep \
 && rm -rf /opt/nianyun/jwt_tool/.git /opt/nianyun/graphql-cop/.git /opt/nianyun/testssl.sh/.git

# ── Stage: final runtime image ──────────────────────────────────────────────
FROM ${NODE_IMAGE} AS control
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
    PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple \
    PIP_DEFAULT_TIMEOUT=300 \
    PIP_RETRIES=5 \
    PATH=/opt/nianyun/bin:/opt/nianyun/node_modules/.bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
# Runtime-only packages. NOTE: no build-essential, no ruby-dev, no git, no Go toolchain.
RUN --mount=type=cache,id=nianyun-apt-cache,target=/var/cache/apt,sharing=locked \
 --mount=type=cache,id=nianyun-apt-lists,target=/var/lib/apt/lists,sharing=locked \
 --mount=type=cache,id=nianyun-playwright,target=/root/.cache/ms-playwright,sharing=locked \
    mkdir -p /etc/ssl/certs \
 && node -e "require('fs').writeFileSync('/etc/ssl/certs/ca-certificates.crt', require('tls').rootCertificates.join('\n') + '\n')" \
 && sed -i \
      -e 's|http://deb.debian.org/debian-security|https://mirrors.aliyun.com/debian-security|g' \
      -e 's|http://deb.debian.org/debian|https://mirrors.aliyun.com/debian|g' \
      /etc/apt/sources.list.d/debian.sources \
 && printf 'Acquire::Retries "5";\n' > /etc/apt/apt.conf.d/80-retries \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl wget libcurl4 bsdextrautils procps \
      python3 ruby ruby-dev build-essential sqlmap \
 && (npx playwright install-deps chromium || npx playwright install-deps chromium || npx playwright install-deps chromium) \
 && npx playwright install chromium \
 && gem install --no-document wpscan \
 && apt-get purge -y --auto-remove ruby-dev build-essential \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /root/.cache/ms-playwright/*/.links 2>/dev/null || true
# Copy compiled tools from the builder stage (no toolchain comes along).
COPY --from=tools /usr/local/bin/ /usr/local/bin/
COPY --from=tools /root/go/bin/ /root/go/bin/
COPY --from=tools /opt/nianyun/tool-venv /opt/nianyun/tool-venv
COPY --from=tools /opt/nianyun/graphql-venv /opt/nianyun/graphql-venv
COPY --from=tools /opt/nianyun/jwt_tool /opt/nianyun/jwt_tool
COPY --from=tools /opt/nianyun/graphql-cop /opt/nianyun/graphql-cop
COPY --from=tools /opt/nianyun/testssl.sh /opt/nianyun/testssl.sh
COPY --from=blackbox-tools /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=blackbox-tools /usr/local/bin/katana /usr/local/bin/katana
COPY --from=blackbox-tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=blackbox-tools /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=blackbox-tools /usr/local/bin/dnsx /usr/local/bin/dnsx
COPY --from=blackbox-tools /usr/local/bin/naabu /usr/local/bin/naabu
COPY --from=blackbox-tools /usr/local/bin/gau /usr/local/bin/gau
COPY --from=blackbox-tools /usr/local/bin/ffuf /usr/local/bin/ffuf
# Application.
COPY --from=build /opt/nianyun/ /opt/nianyun/
COPY deploy/control/config.yaml /opt/nianyun/deploy/control/config.yaml
COPY deploy/control/entrypoint.sh /usr/local/bin/nianyun-control
RUN ln -sf /usr/bin/sqlmap /usr/local/bin/sqlmap \
 && chmod 0755 /usr/local/bin/nianyun-control \
 && mkdir -p /opt/nianyun/data/config
EXPOSE 8700
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8700/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/local/bin/nianyun-control"]
