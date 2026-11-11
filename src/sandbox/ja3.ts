/**
 * TLS ClientHello → JA3 指纹（**只记录，不模拟**）。
 *
 * 2026-11-07 的对照里 `exec.python` 自建请求拿到 403/7149，而同样路径的
 * `http.request` 是 200。差别不只在 UA，也可能在 TLS/JA3 指纹：Python requests
 * 的 ClientHello 与 Chromium 完全不像，风控可以只凭这一层就把脚本挡掉。
 *
 * 现在的 egress 代理对 HTTPS 走 CONNECT 隧道透传，看不到明文头、也改不了
 * CipherSuites。所以第一步是把指纹**记下来**（`/sandbox/egress-log`），
 * 让「同一个 URL 用控制面 / 浏览器 / 沙箱脚本三种出口」有可比的证据。
 * 是否模拟浏览器 JA3 属于另一件事，需要 MITM 终止 TLS，本模块不做。
 */
import { createHash } from "node:crypto";

export type ClientHelloFingerprint = {
  /** JA3 原始串：version,ciphers,extensions,curves,point_formats */
  ja3: string;
  /** JA3 的 MD5（业界习惯用这个值做比对） */
  ja3_hash: string;
  /** ClientHello 里的 SNI（可读域名，便于按目标归类） */
  sni?: string;
  /** 声明的 TLS 版本（十进制，如 771 = TLS1.2） */
  tls_version?: number;
};

/** GREASE 值（0x0a0a、0x1a1a …）不进 JA3，否则同一客户端两次握手指纹会抖。 */
function isGrease(value: number): boolean {
  return (value & 0x0f0f) === 0x0a0a && (value & 0xff) === (value >> 8);
}

function u16(buffer: Buffer, offset: number): number {
  return offset + 2 <= buffer.length ? buffer.readUInt16BE(offset) : 0;
}

/**
 * 从一段可能是 TLS record 的字节里解析 ClientHello。
 * 不完整 / 不是 ClientHello 时返回 undefined——代理不能因为解析失败影响转发。
 */
export function parseClientHello(chunk: Buffer): ClientHelloFingerprint | undefined {
  try {
    if (!Buffer.isBuffer(chunk) || chunk.length < 11) return undefined;
    // TLS record: type(1) version(2) length(2)。允许前面有代理链的多余字节时先找 0x16 0x03。
    let base = 0;
    if (chunk[0] !== 0x16 || chunk[1] !== 0x03) {
      const found = chunk.indexOf(Buffer.from([0x16, 0x03]));
      if (found < 0) return undefined;
      base = found;
    }
    const recordLength = u16(chunk, base + 3);
    if (recordLength < 4) return undefined;
    let offset = base + 5;
    if (chunk[offset] !== 0x01) return undefined; // handshake type: ClientHello
    const handshakeLength = (chunk[offset + 1]! << 16) | (chunk[offset + 2]! << 8) | chunk[offset + 3]!;
    offset += 4;
    const end = Math.min(chunk.length, offset + handshakeLength);
    if (end - offset < 34) return undefined;

    const tlsVersion = u16(chunk, offset);
    offset += 2 + 32; // client_version + random
    const sessionLength = chunk[offset] ?? 0;
    offset += 1 + sessionLength;
    const cipherLength = u16(chunk, offset);
    offset += 2;
    const ciphers: number[] = [];
    for (let index = 0; index + 1 < cipherLength && offset + 1 < end; index += 2) {
      const value = u16(chunk, offset);
      if (!isGrease(value)) ciphers.push(value);
      offset += 2;
    }
    const compressionLength = chunk[offset] ?? 0;
    offset += 1 + compressionLength;
    if (offset + 2 > end) return { ...finish(tlsVersion, ciphers, [], [], []), };

    const extensionsLength = u16(chunk, offset);
    offset += 2;
    const extEnd = Math.min(end, offset + extensionsLength);
    const extensions: number[] = [];
    let curves: number[] = [];
    let formats: number[] = [];
    let sni: string | undefined;
    while (offset + 4 <= extEnd) {
      const type = u16(chunk, offset);
      const length = u16(chunk, offset + 2);
      offset += 4;
      const body = chunk.subarray(offset, Math.min(offset + length, extEnd));
      offset += length;
      if (!isGrease(type)) extensions.push(type);
      if (type === 0x000a && body.length >= 2) { // supported_groups
        const listLength = u16(body, 0);
        for (let index = 2; index + 1 < Math.min(body.length, 2 + listLength); index += 2) {
          const value = u16(body, index);
          if (!isGrease(value)) curves.push(value);
        }
      } else if (type === 0x000b && body.length >= 1) { // ec_point_formats
        for (let index = 1; index < Math.min(body.length, 1 + body[0]!); index += 1) formats.push(body[index]!);
      } else if (type === 0x0000 && body.length >= 5) { // server_name
        // list_len(2) type(1) name_len(2) name
        const nameLength = u16(body, 3);
        const name = body.subarray(5, 5 + nameLength).toString("utf8");
        if (name) sni = name;
      }
    }
    return finish(tlsVersion, ciphers, extensions, curves, formats, sni);
  } catch {
    return undefined;
  }
}

function finish(
  tlsVersion: number,
  ciphers: number[],
  extensions: number[],
  curves: number[],
  formats: number[],
  sni?: string,
): ClientHelloFingerprint {
  const ja3 = [
    String(tlsVersion),
    ciphers.join("-"),
    extensions.join("-"),
    curves.join("-"),
    formats.join("-"),
  ].join(",");
  return {
    ja3,
    ja3_hash: createHash("md5").update(ja3).digest("hex"),
    ...(sni ? { sni } : {}),
    tls_version: tlsVersion,
  };
}
