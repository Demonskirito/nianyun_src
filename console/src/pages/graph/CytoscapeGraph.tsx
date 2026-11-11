/**
 * Cytoscape 实例封装。
 *
 * 只暴露三件事：换数据、跑布局、给节点加 class（高亮/淡出）。
 * 所有"该高亮谁"的判断都在页面层，组件本身不懂业务。
 */
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import dagre from "cytoscape-dagre";
import { useEffect, useRef } from "react";
import { concentricLayout, dagreLayout, graphStyles, journeyLayout } from "./graphStyles";

let registered = false;
function ensureDagre(): void {
  if (registered) return;
  try {
    cytoscape.use(dagre as never);
  } catch {
    // 重复注册/环境不支持时不影响渲染，布局会退回 concentric。
  }
  registered = true;
}

export type GraphHandle = { fit: () => void };

export function CytoscapeGraph(props: {
  elements: ElementDefinition[];
  layout?: "journey" | "dagre" | "concentric";
  onSelect?: (nodeId: string, data: Record<string, unknown>) => void;
  highlight?: { nodes: string[]; edges: string[] } | null;
  onReady?: (handle: GraphHandle) => void;
  height?: number;
}): JSX.Element {
  const container = useRef<HTMLDivElement | null>(null);
  const cy = useRef<Core | null>(null);

  // 初始化：只做一次
  useEffect(() => {
    if (!container.current || cy.current) return;
    ensureDagre();
    const instance = cytoscape({
      container: container.current,
      elements: [],
      style: graphStyles,
      wheelSensitivity: 0.2,
      minZoom: 0.15,
      maxZoom: 3,
    });
    instance.on("tap", "node", event => {
      const node = event.target;
      props.onSelect?.(String(node.id()), node.data());
    });
    cy.current = instance;
    props.onReady?.({ fit: () => instance.fit(undefined, 24) });
    return () => {
      instance.destroy();
      cy.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 换数据：增量更新而不是重建（保住缩放与拖拽位置）
  useEffect(() => {
    const instance = cy.current;
    if (!instance) return;
    const incoming = new Set(props.elements.map(element => String(element.data.id)));
    instance.elements().forEach(element => { if (!incoming.has(String(element.id()))) element.remove(); });
    const existing = new Set(instance.elements().map(element => String(element.id())));
    const added = props.elements.filter(element => !existing.has(String(element.data.id)));
    if (added.length) instance.add(added);
    if (props.elements.length) {
      // 三种布局：journey（横轴=轮次，默认）/ dagre（拓扑左→右）/ concentric（>400 节点兜底）。
      // 默认不再无脑 dagre：拓扑只有 2 跳时它会画成"一竖列"，那正是"看不出历程"的观感来源。
      const chosen = props.layout === "journey"
        ? journeyLayout(props.elements as never)
        : props.layout === "concentric"
          ? concentricLayout
          : props.elements.length > 400 ? concentricLayout : dagreLayout;
      instance.layout(chosen as never).run();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.elements]);

  // 高亮：Kill Chain / 聚焦
  useEffect(() => {
    const instance = cy.current;
    if (!instance) return;
    instance.elements().removeClass("path faded");
    if (!props.highlight) return;
    const keep = new Set([...props.highlight.nodes, ...props.highlight.edges]);
    instance.elements().forEach(element => {
      if (keep.has(String(element.id()))) element.addClass("path");
      else element.addClass("faded");
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.highlight]);

  return <div ref={container} style={{ width: "100%", height: props.height ?? 620, background: "#fbfbfd", borderRadius: 8, border: "1px solid #eee" }} />;
}