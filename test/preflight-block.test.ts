import { describe, expect, it } from "vitest";
import { preflightBlock } from "../src/blackbox/preflight_block.js";

describe("物理边界拦截器（raw TCP/DNS）", () => {
  it("bash 里裸调 naabu/nmap/subfinder/dnsx 直接 126", () => {
    for (const [code, use] of [
      ["naabu -host bdev.oppo.com -p 1-1000", "recon.ports"],
      ["nmap -sV 10.0.0.1", "recon.ports"],
      ["subfinder -d oppo.com -all", "recon.subdomains"],
      ["dnsx -l subs.txt -a", "recon.dns"],
    ] as const) {
      const block = preflightBlock("bash", code);
      expect(block, code).toBeTruthy();
      expect(block!.exit_code).toBe(126);
      expect(block!.stderr).toContain("BLOCKED: Raw TCP/DNS not available in sandbox.");
      expect(block!.stderr).toContain(use);
      expect(block!.stderr).toContain("/state/rpc/requests.jsonl");
    }
  });

  it("命令位置判定：管道/分号/sudo 之后也算，grep 参数不算", () => {
    expect(preflightBlock("bash", "curl -s http://x | nmap -iL -")).toBeTruthy();
    expect(preflightBlock("bash", "cd /tmp; naabu -p 80 -host x")).toBeTruthy();
    expect(preflightBlock("bash", "sudo nmap -p80 x")).toBeTruthy();
    // 只是把这几个词当参数/字符串，不该拦
    expect(preflightBlock("bash", "grep -r 'nmap' /opt/notes.txt")).toBeUndefined();
    expect(preflightBlock("bash", "echo naabu")).toBeUndefined();
  });

  it("python 里 socket DNS / raw connect / dnspython 都拦", () => {
    expect(preflightBlock("python", "import socket\nprint(socket.gethostbyname('a.com'))")).toBeTruthy();
    expect(preflightBlock("python", "import socket\ns=socket.create_connection(('1.1.1.1', 443))")).toBeTruthy();
    expect(preflightBlock("python", "import dns.resolver\nprint(dns.resolver.resolve('a.com'))")).toBeTruthy();
    expect(preflightBlock("python", "import subprocess\nsubprocess.run(['naabu','-host','x'])")).toBeTruthy();
  });

  it("正常沙箱任务不误伤", () => {
    const allowed = [
      "python",
      "bash",
    ];
    expect(preflightBlock(allowed[0], "import hmac, hashlib\nsig = hmac.new(b'k', b'm', hashlib.sha256).hexdigest()\nprint(sig)")).toBeUndefined();
    expect(preflightBlock(allowed[0], "import requests\nprint(requests.get('http://target/api', proxies={'http':'http://sandbox:8899'}).status_code)")).toBeUndefined();
    expect(preflightBlock(allowed[1], "curl -s -x http://sandbox:8899 http://target/ -o /state/home.html && wc -c /state/home.html")).toBeUndefined();
    expect(preflightBlock(allowed[1], "cat /state/recon/endpoints.json | python3 -m json.tool | head")).toBeUndefined();
  });

  it("空脚本与纯注释不拦", () => {
    expect(preflightBlock("bash", "")).toBeUndefined();
    expect(preflightBlock("python", "   \n\t")).toBeUndefined();
    expect(preflightBlock("bash", "# naabu 不可用，端口走 recon.ports\n")).toBeUndefined();
  });

  it("stderr 带命中片段，模型能看懂为什么被拦", () => {
    const block = preflightBlock("bash", "naabu -host target -p 443")!;
    expect(block.stderr).toContain("naabu");
    expect(block.hints[0]?.use).toBe("recon.ports");
    expect(block.hints[0]?.why).toMatch(/raw TCP/);
  });
});