"""生成 SRC 攻击历程图（单页 PNG）。

数据来源（都在代码里，不是手写想象）：
  src/blackbox/route-manifest.ts  6 步路线（surface/baseline/select/sandbox/radio/converge）
  src/blackbox/playbooks.ts       15 条打法（id/优先级/timebox/步骤）
  src/blackbox/tool_manifest.ts   74 项工具（层级 T/S/R、权重）
  src/blackbox/rules.ts           15 节规则文档 + 聚焦锁 / 鉴权墙 / 循环控制默认值
  src/blackbox/agent.ts           主 Agent 硬规则 + TACTICAL_OBSERVER_RULES
  src/blackbox/progress.ts        墙信号 / 补枪 / 战例库 / 死胡同 / 零熵熔断
"""

from __future__ import annotations

from PIL import Image, ImageDraw, ImageFont

FONT = r"C:\Windows\Fonts\msyh.ttc"
FONT_BOLD = r"C:\Windows\Fonts\msyhbd.ttc"

W, H = 2360, 3200
X0 = 44
COL_STAGE = (X0, 336)
COL_CHIP = (352, 1452)
COL_RIGHT = (1468, 2316)

INK = (15, 23, 42)
MUTED = (71, 85, 105)
PAPER = (248, 250, 252)
LINE = (203, 213, 225)

STAGE_FILL = (30, 41, 59)
TACTICAL = ((37, 99, 235), (219, 234, 254))
STRATEGIC = ((124, 58, 237), (237, 233, 254))
HEAVY = ((234, 88, 12), (255, 237, 213))
WALL = ((220, 38, 38), (254, 226, 226))
EVIDENCE = ((5, 150, 105), (209, 250, 229))
NEUTRAL = ((71, 85, 105), (241, 245, 249))

STAGES = [
    {
        "no": "1",
        "name": "铺面",
        "en": "surface",
        "goal": "把资产与入口列出来：\n范围锁定在会话资产，不越界",
        "chips": [
            ("recon.subdomains", TACTICAL), ("recon.dns", TACTICAL), ("recon.http_probe", TACTICAL),
            ("recon.ports", TACTICAL), ("recon.tls", TACTICAL), ("recon.cms", TACTICAL),
            ("recon.historical_urls", TACTICAL), ("recon.wordlists", TACTICAL), ("katana.crawl", TACTICAL),
            ("recon.js_endpoints", TACTICAL),
        ],
        "right": [
            "graph_drift 欠账：图里从未被请求过的根节点必须先补打（带可复制模板）",
            "soft_404（≥2 路径同尺寸 200）→ 目录爆破全是假阳性，改 JS 端点",
            "spa_shell（HTML 同尺寸）→ 缴械步兵，改抓真实 XHR",
            "重型扫描器权重 3–5，fast 模式直接 budget_degraded",
        ],
    },
    {
        "no": "2",
        "name": "基线",
        "en": "baseline",
        "goal": "先看 Burp 的脸色：\n每个新 host / 新目录先读一次流量",
        "chips": [
            ("burp.history + analysis", TACTICAL), ("http.diff 基线", TACTICAL), ("burp.sitemap", TACTICAL),
            ("burp.entry", TACTICAL), ("burp.cookies", TACTICAL), ("浏览器壳 browser.open", TACTICAL),
            ("项目 Cookie 罐 / 全局 Token 罐", TACTICAL),
        ],
        "right": [
            "8 个 signals：authwall / waf_suspected / volatile_param / static_response / size_variance / soft_404 / burst / spa_shell",
            "全站 301/302 或 catch-all → 换三种利用：Host 头注入、开放重定向、CNAME 悬垂接管",
            "static_response 拿来当 diff 基线；size_variance 先 diff 最大最小两条",
            "未授权证据必须能发匿名请求：anonymous:true 跳过 Cookie/Token 罐",
        ],
    },
    {
        "no": "3",
        "name": "选点",
        "en": "select",
        "goal": "假设优先：\n打 high 假设边，不打无关端点",
        "chips": [
            ("attack_graph 地图", TACTICAL), ("graph_next_hops 寻路", TACTICAL),
            ("hypotheses(severity=high)", TACTICAL), ("dead_ends 死胡同", TACTICAL),
            ("identities 身份", TACTICAL), ("focus_lock 焦点锁", TACTICAL),
        ],
        "right": [
            "参数带签名/加密/timestamp/nonce → 步兵重放必失败，转特种兵逆签名",
            "burst（≥5 条 /2s）→ 用 recon.race_condition 复现并发",
            "每任务最多 8 回合 / 50 权重；停滞 3 轮换打法，不换参数重试",
            "viewport：reject_unassigned=false，未派活请求仍可发，但不计焦点",
        ],
    },
    {
        "no": "4",
        "name": "打点",
        "en": "playbooks",
        "goal": "15 条固定套路，\nconfirm 拿到才算完成",
        "chips": [
            ("unauth_exposure p1", TACTICAL), ("auth_token p2", TACTICAL), ("idor p3", TACTICAL),
            ("sqli p4", HEAVY), ("upload_rce p5", TACTICAL), ("cmdi p6", TACTICAL),
            ("ssrf p7", TACTICAL), ("deserialization p8", HEAVY), ("jwt_auth p9", TACTICAL),
            ("cloud_supply p10", TACTICAL), ("logic p11", TACTICAL), ("race_condition p12", STRATEGIC),
            ("graphql_ws p13", TACTICAL), ("xss p14", HEAVY), ("waf_bypass p0", WALL),
        ],
        "right": [
            "timebox 600–1500s：到点拿不到 confirm 就写 stop 理由并换下一条",
            "401/403/10403 ≠ 完成：blocked_by_auth + 说明缺哪种凭证",
            "无回显一律 OAST（recon.interactsh）；时序差用 timing_delta 才算确认",
            "写操作（下单/改密/上传）真做一次并写预期影响，优先可逆",
            "task_pending_limit=12：任务堆太多会互相挤占，先打高优先级",
        ],
    },
    {
        "no": "5",
        "name": "特种兵 + 电台",
        "en": "sandbox / radio",
        "goal": "签名逆向、批量动作、\n沙箱里排队由控制面发射",
        "chips": [
            ("exec.python（沙箱）", STRATEGIC), ("exec.bash（沙箱）", STRATEGIC),
            ("/state 产物跨调用", STRATEGIC), ("dispatch.jsonl 队列", STRATEGIC),
            ("recon.race_condition 并发射", STRATEGIC), ("recon.scan_profile 协商参数", TACTICAL),
            ("fs.list / fs.read / fs.grep", TACTICAL), ("recon.interactsh OAST", TACTICAL),
        ],
        "right": [
            "一次 exec 只干一件事，结构化 JSON 写进 /state 供下游脚本读",
            "出站强制走 MITM 代理；缺能力就写 tool_gaps 上报，不硬凑 http.request",
            "竞态必须 20 并发一次发（串行 for 不算竞态，结果不能当证据）",
            "沙箱超时 ≤300s，产物带回 workspace 再用 fs.* 分析",
        ],
    },
    {
        "no": "6",
        "name": "墙与绕行",
        "en": "waf / auth_wall",
        "goal": "墙是第一条要打的墙，\n不是终点",
        "chips": [
            ("战例库复刻 waf_ledger", WALL), ("0 产出补枪（根路径两枪）", WALL),
            ("编码矩阵 exec.python", WALL), ("参数污染", WALL), ("路径规范化", WALL),
            ("方法转换 burp.send", WALL), ("白名单伪装 UA+XFF", WALL),
            ("原始报文/分块", WALL), ("负载夹带 burp.send_batch", WALL),
            ("横向逃逸 lateral_escape", WALL),
        ],
        "right": [
            "判墙：同路径两次 status+bytes+body_sha256 三项一致才算 WAF（不一致是限流/静态兜底）",
            "鉴权墙三放行：unauth/jwt 打法任务、19 条敏感路径字典、bypass_auth_wall=true",
            "阶梯没跑满或没有 baseline/hit 对照 → 不许记 blocked",
            "出现 429 / 人机挑战（CF challenge、滑块、captcha）立即停手，别把出口 IP 打死",
            "打穿必须回报 waf_bypasses → 落库 → 下一轮先照抄",
        ],
    },
    {
        "no": "7",
        "name": "收敛收口",
        "en": "converge",
        "goal": "证据说话：\n没有 ev-id 不说话",
        "chips": [
            ("http.diff verdict", EVIDENCE), ("identical / same_shape", EVIDENCE),
            ("different / timing_delta", EVIDENCE), ("closureAudit 结案三件套", EVIDENCE),
            ("Evidence Ledger ev-…", EVIDENCE), ("findings → Observer 裁决", EVIDENCE),
            ("报告（区分未完成）", EVIDENCE),
        ],
        "right": [
            "结案三件套：① http.diff verdict ② 请求真发出去的证据 ③ 否定证据；缺一件只能 blocked",
            "findings 由 Observer 裁决为 confirmed / needs_evidence / rejected，主 Agent 不得自称已确认",
            "只带拒绝证据的结案会被调度器拒绝并转 blocked",
            "报告必须区分已完成 / 失败 / 受阻 / 未执行",
        ],
    },
]

OBSERVER_BOXES = [
    ("审什么（只读）", [
        "覆盖率、重复动作、停滞、异常响应、证据质量、预算风险",
        "架构特征：全站跳转 / 统一 10403 / WAF 页 / OSS 直链 / catch-all / 跨域 SDK",
        "空洞审查（\"建议继续测试\"）视为无效输出",
    ]),
    ("产出什么（结构化）", [
        "next_steps[{tool,target,input,why}]：工具取自 74 项枚举，写错整条被拒",
        "supplemental_tasks：可绑定 playbook 的补充任务",
        "finding_reviews：confirmed / needs_evidence / rejected（可点名缺哪一步证据）",
        "decision：continue / finish / pause（pause 必须给具体 pause_reason）",
    ]),
    ("硬权限边界", [
        "只读参谋：从不执行工具，不能替主 Agent 发请求",
        "确认权在它手上，但必须引用该发现已引用的成功工具结果",
        "建议上限 6 条 pending，连续 2 轮未被采纳自动失效",
        "过期快照：建议保留、门禁重算，不永久卡死",
    ]),
    ("怎么回灌", [
        "critical_actions.advice → 下一轮必须逐条写 advice_decisions",
        "system_interrupts → 后台插话，看到即用完，不阻塞计划",
        "review-stale / review-conflict / observer-async-error 都留事件痕",
    ]),
]


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_BOLD if bold else FONT, size)


def wrap(draw: ImageDraw.ImageDraw, text: str, face: ImageFont.FreeTypeFont, width: int) -> list[str]:
    lines: list[str] = []
    for raw in text.split("\n"):
        if not raw:
            lines.append("")
            continue
        current = ""
        for ch in raw:
            if draw.textlength(current + ch, font=face) > width and current:
                lines.append(current)
                current = ch
            else:
                current += ch
        lines.append(current)
    return lines


def rounded(draw: ImageDraw.ImageDraw, box, fill, outline=None, radius: int = 10, width: int = 1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def main() -> None:
    image = Image.new("RGB", (W, H), (255, 255, 255))
    draw = ImageDraw.Draw(image)
    f_title = font(44, True)
    f_sub = font(20)
    f_stage_no = font(40, True)
    f_stage = font(30, True)
    f_stage_en = font(19)
    f_goal = font(19)
    f_chip = font(19)
    f_right = font(19)
    f_head = font(21, True)
    f_small = font(17)

    # ── 标题 ──
    draw.text((X0, 34), "Nianyun · SRC 黑盒攻击历程", font=f_title, fill=INK)
    draw.text((X0, 96), "主 Agent 7 阶段主线 · 15 条打法 · 74 项工具 · 调度器硬约束 · Observer 旁路（数据取自代码，非示意）", font=f_sub, fill=MUTED)

    # ── 列头 ──
    head_y = 138
    for (x0, x1), label in ((COL_STAGE, "阶段"), (COL_CHIP, "动作 / 工具"), (COL_RIGHT, "触发信号与硬约束")):
        rounded(draw, (x0, head_y, x1, head_y + 40), STAGE_FILL, radius=8)
        draw.text((x0 + 16, head_y + 9), label, font=f_head, fill=(255, 255, 255))

    y = head_y + 56
    row_gap = 16
    problems: list[str] = []

    for stage in STAGES:
        sx0, sx1 = COL_STAGE
        cx0, cx1 = COL_CHIP
        rx0, rx1 = COL_RIGHT

        # 先算内容高度：chips 换行 + 右侧文本行数
        chip_rows: list[list[tuple[str, tuple]]] = []
        current: list[tuple[str, tuple]] = []
        current_w = 0
        for name, color in stage["chips"]:
            box_w = draw.textlength(name, font=f_chip) + 34
            if current and current_w + box_w + 12 > (cx1 - cx0 - 32):
                chip_rows.append(current)
                current, current_w = [], 0
            current.append((name, color))
            current_w += box_w + 12
        if current:
            chip_rows.append(current)

        right_lines = []
        for item in stage["right"]:
            for index, line in enumerate(wrap(draw, "· " + item, f_right, rx1 - rx0 - 36)):
                right_lines.append(line if index == 0 else "  " + line)

        chips_h = len(chip_rows) * 50
        right_h = len(right_lines) * 27
        stage_h = max(chips_h, right_h, 150) + 40

        # 阶段卡
        rounded(draw, (sx0, y, sx1, y + stage_h), (241, 245, 249), outline=LINE, radius=14)
        draw.text((sx0 + 18, y + 12), stage["no"], font=f_stage_no, fill=STAGE_FILL)
        draw.text((sx0 + 74, y + 22), stage["name"], font=f_stage, fill=INK)
        draw.text((sx0 + 74, y + 62), stage["en"], font=f_stage_en, fill=MUTED)
        for index, line in enumerate(wrap(draw, stage["goal"], f_goal, sx1 - sx0 - 40)):
            draw.text((sx0 + 18, y + 96 + index * 25), line, font=f_goal, fill=MUTED)

        # 工具 chips
        cy = y + 18
        for row in chip_rows:
            cx = cx0
            for name, (stroke, fill) in row:
                box_w = draw.textlength(name, font=f_chip) + 34
                rounded(draw, (cx, cy, cx + box_w, cy + 40), fill, outline=stroke, radius=9, width=2)
                draw.text((cx + 17, cy + 9), name, font=f_chip, fill=stroke)
                cx += box_w + 12
                if cx > cx1 - 8:
                    problems.append(f"chip overflow stage {stage['no']}: {name} -> {cx}")
            cy += 50

        # 右侧约束
        ry = y + 20
        for line in right_lines:
            draw.text((rx0 + 16, ry), line, font=f_right, fill=INK if line.startswith("·") else MUTED)
            ry += 27

        # 阶段之间的箭头（主线）
        if stage["no"] != STAGES[-1]["no"]:
            mid = (sx0 + sx1) // 2
            draw.line((mid, y + stage_h, mid, y + stage_h + row_gap), fill=STAGE_FILL, width=4)
            draw.polygon([(mid - 8, y + stage_h + row_gap - 2), (mid + 8, y + stage_h + row_gap - 2), (mid, y + stage_h + row_gap + 9)], fill=STAGE_FILL)

        y += stage_h + row_gap

    # ── Observer 旁路 ──
    y += 8
    bar_h = 40
    rounded(draw, (COL_STAGE[0], y, COL_RIGHT[1], y + bar_h), (79, 70, 229), radius=8)
    draw.text((COL_STAGE[0] + 16, y + 8), "Observer 旁路 · 只读战术参谋（不执行工具，审查每轮证据并在下一轮回灌）", font=f_head, fill=(255, 255, 255))
    y += bar_h + 14

    inner_w = (COL_RIGHT[1] - COL_STAGE[0] - 3 * 16) // 4
    max_h = 0
    bodies: list[tuple[str, list[str]]] = []
    for title, items in OBSERVER_BOXES:
        lines: list[str] = []
        for item in items:
            for index, line in enumerate(wrap(draw, "· " + item, f_small, inner_w - 30)):
                lines.append(line if index == 0 else "  " + line)
        bodies.append((title, lines))
        max_h = max(max_h, len(lines) * 24 + 62)

    for index, (title, lines) in enumerate(bodies):
        bx0 = COL_STAGE[0] + index * (inner_w + 16)
        bx1 = bx0 + inner_w
        rounded(draw, (bx0, y, bx1, y + max_h), (238, 242, 255), outline=(79, 70, 229), radius=12, width=2)
        draw.text((bx0 + 15, y + 12), title, font=f_head, fill=(49, 46, 129))
        for line_index, line in enumerate(lines):
            draw.text((bx0 + 15, y + 46 + line_index * 24), line, font=f_small, fill=INK if line.startswith("·") else MUTED)

    y += max_h + 18

    # ── 图例 ──
    legend = [
        ("步兵 tactical（控制面直发）", TACTICAL),
        ("特种兵 strategic（沙箱内）", STRATEGIC),
        ("重型扫描器 w3–5（预算敏感）", HEAVY),
        ("墙 / 拦截响应", WALL),
        ("证据与裁决", EVIDENCE),
        ("中性机制", NEUTRAL),
    ]
    lx = COL_STAGE[0]
    for label, (stroke, fill) in legend:
        box_w = draw.textlength(label, font=f_small) + 40
        rounded(draw, (lx, y, lx + box_w, y + 34), fill, outline=stroke, radius=8, width=2)
        draw.text((lx + 18, y + 6), label, font=f_small, fill=stroke)
        lx += box_w + 12

    y += 46
    draw.text((COL_STAGE[0], y), "路线 6 步（route-manifest.ts）：surface 铺面 → baseline 基线 → select 选点 → sandbox 特种兵 → radio 电台 → converge 收敛；第 6 行「墙与绕行」是横切闸门，任何阶段撞墙都进这条阶梯。",
              font=f_small, fill=MUTED)

    print("content bottom:", y + 24, "canvas:", H)
    print("problems:", problems if problems else "none")
    image = image.crop((0, 0, W, min(H, y + 40)))
    image.save("docs/attack-journey-src.png", optimize=True)
    print("wrote docs/attack-journey-src.png", image.size)


main()