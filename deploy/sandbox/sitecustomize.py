"""沙箱内的 TLS 兜底（默认不启用）。

为什么需要：job 的出站一律经过 Burp 的 MITM，Burp 用自签 CA 重签证书。Agent 写的
Python POC 默认会校验证书链，于是每次 HTTPS 请求都 SSL: CERTIFICATE_VERIFY_FAILED。
两种正规解法：
  1) 把 Burp CA 挂进来（SANDBOX_CA_PEM）→ REQUESTS_CA_BUNDLE / SSL_CERT_FILE 指过去，真正校验；
  2) 授权实验环境里设 SANDBOX_TLS_INSECURE=1 → 把默认 context 换成不校验（仅此沙箱内生效）。
"""
import os

if os.environ.get("SANDBOX_TLS_INSECURE") == "1":  # noqa: S105 - explicit lab switch
    import ssl

    _unverified = ssl._create_unverified_context  # noqa: SLF001
    ssl._create_default_https_context = _unverified  # noqa: SLF001

    _original_create = ssl.create_default_context
    _original_wrap = getattr(ssl, "wrap_socket", None)

    def _create_default_context(*args, **kwargs):
        context = _original_create(*args, **kwargs)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    ssl.create_default_context = _create_default_context  # type: ignore[assignment]
    if callable(_original_wrap):
        ssl.wrap_socket = lambda *a, **k: _original_wrap(*a, **{**k, "cert_reqs": ssl.CERT_NONE})  # type: ignore[attr-defined]