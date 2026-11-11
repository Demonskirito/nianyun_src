import { useCallback, useEffect, useState } from "react";
import { Button, Form, Input, Popconfirm, Space, Table, Tag, Typography } from "antd";
import { deleteAuthSeed, listAuthSeeds, saveAuthSeed } from "../api";
import { useDesk } from "../store";
import type { AuthSeed } from "../types";

function fmtTime(ts: number): string {
  if (!ts) return "—";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return "—";
  }
}

type Banner = { kind: "ok" | "bad"; msg: string } | null;

export function AuthSeedsPage() {
  const { t } = useDesk();
  const [seeds, setSeeds] = useState<AuthSeed[]>([]);
  const [loading, setLoading] = useState(false);
  const [host, setHost] = useState("");
  const [content, setContent] = useState("");
  const [saving, setSaving] = useState(false);
  const [banner, setBanner] = useState<Banner>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const rec = await listAuthSeeds();
      setSeeds(rec.seeds || []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onSave() {
    if (!host.trim()) {
      setBanner({ kind: "bad", msg: t("authSeedNoHost") });
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      setBanner({ kind: "bad", msg: t("authSeedInvalid") });
      return;
    }
    if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as { cookies?: unknown }).cookies)) {
      setBanner({ kind: "bad", msg: t("authSeedInvalid") });
      return;
    }
    setSaving(true);
    setBanner(null);
    try {
      const rec = await saveAuthSeed(host.trim(), content);
      if (rec.ok) {
        setBanner({ kind: "ok", msg: `${host.trim()} 已保存` });
        setHost("");
        setContent("");
        await load();
      } else {
        setBanner({ kind: "bad", msg: rec.error || "保存失败" });
      }
    } catch (e) {
      setBanner({ kind: "bad", msg: String(e) });
    } finally {
      setSaving(false);
    }
  }

  async function onDelete(h: string) {
    const rec = await deleteAuthSeed(h);
    if (rec.ok) {
      setBanner({ kind: "ok", msg: `${h} 已删除` });
      await load();
    } else {
      setBanner({ kind: "bad", msg: rec.error || "删除失败" });
    }
  }

  const columns = [
    { title: t("authSeedHost"), dataIndex: "host", key: "host", render: (v: string) => <code>{v}</code> },
    { title: t("authSeedCookies"), dataIndex: "cookies", key: "cookies", width: 100 },
    {
      title: t("authSeedLS"),
      key: "ls",
      render: (_: unknown, row: AuthSeed) => (
        <Space wrap size={[4, 4]}>
          {row.localStorageKeys.slice(0, 8).map((k) => (
            <Tag key={k}>{k}</Tag>
          ))}
          {row.localStorageKeys.length > 8 ? <Tag>+{row.localStorageKeys.length - 8}</Tag> : null}
          {row.localStorageKeys.length === 0 ? <Typography.Text type="secondary">—</Typography.Text> : null}
        </Space>
      ),
    },
    { title: t("authSeedUpdated"), dataIndex: "updated_at", key: "updated_at", width: 180, render: (v: number) => fmtTime(v) },
    {
      title: "",
      key: "action",
      width: 90,
      render: (_: unknown, row: AuthSeed) => (
        <Popconfirm
          title={t("authSeedConfirmDelete")}
          okText={t("authSeedDelete")}
          cancelText={t("authSeedCancel")}
          onConfirm={() => void onDelete(row.host)}
        >
          <Button danger size="small">{t("authSeedDelete")}</Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <section className="page auth-seeds-page">
      {banner ? <p className={"flash " + banner.kind}>{banner.msg}</p> : null}

      <section className="sheet">
        <header className="sheet-head">
          <h3>{t("authSeedsTitle")}</h3>
          <p className="sheet-lede">{t("authSeedsLede")}</p>
        </header>

        <Table
          rowKey="host"
          loading={loading}
          dataSource={seeds}
          columns={columns}
          pagination={false}
          locale={{ emptyText: t("authSeedEmpty") }}
          size="small"
        />

        <p className="help">{t("authSeedTip")}</p>
      </section>

      <section className="sheet">
        <header className="sheet-head">
          <h3>{t("authSeedSave")}</h3>
        </header>
        <Form layout="vertical" onFinish={onSave}>
          <div className="form-grid">
            <div className="field">
              <label htmlFor="seed-host">{t("authSeedHost")}</label>
              <Input id="seed-host" value={host} placeholder={t("authSeedHostPh")} onChange={(e) => setHost(e.target.value)} />
            </div>
          </div>
          <div className="field">
            <label htmlFor="seed-content">{t("authSeedContent")}</label>
            <Input.TextArea id="seed-content" rows={10} value={content} placeholder={t("authSeedContentPh")} onChange={(e) => setContent(e.target.value)} />
          </div>
          <div className="sheet-foot">
            <Button type="primary" htmlType="submit" loading={saving}>{t("authSeedSave")}</Button>
          </div>
        </Form>
      </section>
    </section>
  );
}
