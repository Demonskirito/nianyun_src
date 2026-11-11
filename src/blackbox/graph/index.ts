/**
 * Agent 历程图（Attack Graph）—— 对外出口。
 *
 * 用法（控制面）：
 *   const state = graphState(progress.state.graph);
 *   ingestToolResult(state, { tool: "http.request", endpoints: [{ url, status_code }] });
 *   progress.state.graph = state;
 *
 * 决策点只有两个：
 *   - 上下文：`graphContextView(state)` → `context.attack_graph`
 *   - 执行器：`deadEndOf(state, url)` → 拒绝再打（见 routing / desk 的拦截）
 */
export * from "./types.js";
export * from "./endpoint.js";
export * from "./evidence.js";
export * from "./builder.js";
export * from "./hypotheses.js";
export * from "./serialize.js";
export * from "./rank.js";
export * from "./analyze.js";
export * from "./pathfind.js";
export * from "./visual.js";