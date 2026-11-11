# Sandbox Service 镜像（可信组件）。
#
# 只有这个容器持有 /var/run/docker.sock：控制面容器永远不挂。
# docker CLI 从官方 cli 镜像里取，避免在构建期拉 apk 包（离线/代理受限也能构建）。
# syntax=docker/dockerfile:1.7
FROM node:22.22.0-bookworm-slim

COPY --from=docker:29.3.0-cli /usr/local/bin/docker /usr/local/bin/docker

# 只跑沙箱服务的编排逻辑，不需要 playwright/浏览器。
WORKDIR /opt/nianyun-sandbox
COPY server/ /opt/nianyun-sandbox/dist/
COPY package.json /opt/nianyun-sandbox/package.json

RUN mkdir -p /var/lib/nianyun-sandbox/jobs \
 && groupadd -r sandbox 2>/dev/null || true \
 && useradd -r -g sandbox -u 10001 sandbox 2>/dev/null || true \
 && chown -R sandbox:sandbox /var/lib/nianyun-sandbox

ENV NODE_ENV=production \
    SANDBOX_HOST=0.0.0.0 \
    SANDBOX_PORT=8790 \
    SANDBOX_PROXY_PORT=8899 \
    SANDBOX_JOBS_DIR=/var/lib/nianyun-sandbox/jobs

EXPOSE 8790 8899
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8790/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# 需要 docker 套接字来拉起 job 容器；gVisor 时把 SANDBOX_RUNTIME 设为 runsc。
ENTRYPOINT ["node", "/opt/nianyun-sandbox/dist/sandbox/server.js"]