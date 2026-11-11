import { useEffect } from "react";
import { Button, Card, Col, List, Row, Space, Statistic, Tag, Typography } from "antd";
import {
  ProjectOutlined,
  RadarChartOutlined,
  DesktopOutlined,
  BugOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { useDesk } from "../store";
import type { Project } from "../types";

const num = (value: unknown) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
};

function fmtTime(ts: number | undefined, lang: string) {
  const n = Number(ts);
  if (!n) return "—";
  const d = new Date(n * 1000);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(lang === "en" ? "en-GB" : "zh-CN", { hour12: false });
}

export function HomePage() {
  const { t, lang, projects, status, currentProject, displayProjectName, displayProjectNote, selectProject, loadWorkspace, loadStatus } = useDesk();
  const nav = useNavigate();

  useEffect(() => {
    void loadWorkspace();
    void loadStatus();
  }, [loadWorkspace, loadStatus]);

  const projectCount = status.project_count != null ? num(status.project_count) : projects.length;
  const candidateCount = status.candidate_count != null
    ? num(status.candidate_count)
    : projects.reduce((n, p) => n + num(p.candidate_count), 0);
  const sessionCount = status.session_count != null
    ? num(status.session_count)
    : projects.reduce((n, p) => n + num(p.session_count), 0);
  const activeSessions = status.active_sessions != null
    ? num(status.active_sessions)
    : projects.reduce((n, p) => n + num(p.running), 0);
  const findingCount = status.finding_count != null
    ? num(status.finding_count)
    : projects.reduce((n, p) => n + num(p.finding_count), 0);
  const mode = status.execution?.mode;
  const modeLabel = mode === "execute" ? t("execExecute") : mode === "inspect" ? t("execInspect") : t("execServe");

  function openProject(project: Project, target: "assets" | "blackbox") {
    void selectProject(project.id);
    nav(target === "assets" ? "/assets" : `/blackbox?project=${encodeURIComponent(project.id)}`);
  }

  return (
    <div className="page">
      <Row gutter={[16, 16]}>
        <Col xs={12} lg={6}>
          <Card>
            <Statistic title={t("statProjects")} value={projectCount} prefix={<ProjectOutlined />} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card>
            <Statistic title={t("statCandidates")} value={candidateCount} prefix={<RadarChartOutlined />} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card>
            <Statistic
              title={t("statSessions")}
              value={sessionCount}
              prefix={<DesktopOutlined />}
              suffix={activeSessions ? <span style={{ marginInlineStart: 8, fontSize: 12 }}><ThunderboltOutlined /> {t("statRunning")} {activeSessions}</span> : undefined}
            />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card>
            <Statistic title={t("statFindings")} value={findingCount} prefix={<BugOutlined />} />
          </Card>
        </Col>
      </Row>

      <Card
        title={t("homeProjects")}
        className="home-projects"
        style={{ marginTop: 16 }}
        extra={mode ? <Tag>{t("execMode")} · {modeLabel}</Tag> : null}
      >
        <Typography.Paragraph type="secondary" className="home-projects-lede">
          {t("homeProjectsLede")}
        </Typography.Paragraph>
        <List
          size="small"
          dataSource={projects}
          locale={{ emptyText: t("homeNoProjects") }}
          renderItem={(p) => {
            const selected = currentProject()?.id === p.id;
            return (
              <List.Item
                style={selected ? { background: "rgba(127, 127, 127, 0.08)" } : undefined}
                actions={[
                  <Button key="assets" size="small" type="link" onClick={() => openProject(p, "assets")}>{t("homeOpenAssets")}</Button>,
                  <Button key="blackbox" size="small" type="link" onClick={() => openProject(p, "blackbox")}>{t("homeOpenBlackbox")}</Button>,
                ]}
              >
                <List.Item.Meta
                  title={
                    <Space size={8} wrap>
                      <span>{displayProjectName(p)}</span>
                      {num(p.running) ? <Tag color="processing">{t("homeProjectRunning", { n: num(p.running) })}</Tag> : null}
                    </Space>
                  }
                  description={
                    <Space direction="vertical" size={2}>
                      <span>{displayProjectNote(p)}</span>
                      <span>
                        {t("homeProjectMeta", {
                          candidates: num(p.candidate_count),
                          sessions: num(p.session_count),
                          findings: num(p.finding_count),
                        })}
                      </span>
                      <span className="help">{t("homeUpdated", { time: fmtTime(p.updated_at, lang) })}</span>
                    </Space>
                  }
                />
              </List.Item>
            );
          }}
        />
      </Card>
    </div>
  );
}
