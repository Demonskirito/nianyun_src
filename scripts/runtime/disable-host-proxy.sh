#!/usr/bin/env bash
# Remove the standard Docker/apt proxy overrides after backing them up.
# Run explicitly as root; Nianyun never changes host services on startup.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: bash scripts/runtime/disable-host-proxy.sh" >&2
  exit 1
fi

proxy_files=(
  /etc/systemd/system/docker.service.d/http-proxy.conf
  /etc/apt/apt.conf.d/95proxies
)
# Refuse to move a file if it also contains unrelated configuration.
for path in "${proxy_files[@]}"; do
  [[ -f "$path" ]] || continue
  case "$path" in
    */http-proxy.conf)
      if grep -Ev '^[[:space:]]*($|#|;|\[Service\][[:space:]]*$|Environment="(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|FTP_PROXY|NO_PROXY|http_proxy|https_proxy|all_proxy|ftp_proxy|no_proxy)=[^"]*"[[:space:]]*$)' "$path" | grep -q .; then
        echo "Mixed settings in $path; review this file before removing proxy entries." >&2
        exit 1
      fi
      ;;
    */95proxies)
      if grep -Eiv '^[[:space:]]*($|//|#|Acquire::(http|https|ftp)::Proxy[[:space:]]+"[^"]*";[[:space:]]*$)' "$path" | grep -q .; then
        echo "Mixed settings in $path; review this file before removing proxy entries." >&2
        exit 1
      fi
      ;;
  esac
done

backup_dir=$(mktemp -d /var/backups/nianyun-proxy.XXXXXXXX)
for path in "${proxy_files[@]}"; do
  if [[ -f "$path" ]]; then
    cp -p -- "$path" "$backup_dir/$(basename "$path")"
    rm -- "$path"
  fi
done
echo "Proxy config backup: $backup_dir"
systemctl daemon-reload
systemctl restart docker
docker info --format 'Docker HTTP proxy: {{.HTTPProxy}}; HTTPS proxy: {{.HTTPSProxy}}; bypass: {{.NoProxy}}'
