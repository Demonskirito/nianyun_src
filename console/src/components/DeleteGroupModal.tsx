/**
 * 删除整个资产分组（= 一个项目，含它下面的全部黑盒会话）。
 *
 * 为什么要输入分组名：这是控制台里唯一一个"点两下就再也回不来"的操作——
 * 会话、证据、产物文件、候选资产、发现记录一起没。`Modal.confirm` 的默认确认框
 * 在连续操作时点错的概率太高，所以要求手打名字。
 */
import { useEffect, useState } from "react";
import { Alert, Input, Modal, Typography } from "antd";

const { Text } = Typography;

export type DeleteGroupTarget = {
  id: string;
  name: string;
  /** 会被一起删掉的会话数（说清楚，别让人猜）。 */
  sessions?: number;
  candidates?: number;
};

export function DeleteGroupModal(props: {
  target: DeleteGroupTarget | null;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}): JSX.Element {
  const [typed, setTyped] = useState("");
  useEffect(() => { setTyped(""); }, [props.target?.id]);

  const name = props.target?.name || "";
  const matched = typed.trim() === name.trim() && name.trim().length > 0;

  return (
    <Modal
      open={Boolean(props.target)}
      title="删除整个资产分组？"
      okText="删除分组"
      cancelText="取消"
      okButtonProps={{ danger: true, disabled: !matched, loading: props.busy }}
      onOk={props.onConfirm}
      onCancel={props.onCancel}
      destroyOnClose
    >
      <Alert
        type="error" showIcon style={{ marginBottom: 12 }}
        message="这个操作不可恢复"
        description={
          <span>
            分组「<Text strong>{name}</Text>」及其
            {typeof props.target?.sessions === "number" ? <> <Text strong>{props.target.sessions}</Text> 个黑盒会话、</> : "全部会话、"}
            证据账本、产物文件、候选资产、发现记录都会被删除。
          </span>
        }
      />
      <p style={{ marginBottom: 6 }}>确认请输入分组名 <Text code>{name}</Text>：</p>
      <Input
        value={typed} autoFocus placeholder={name}
        onChange={(event) => setTyped(event.target.value)}
        onPressEnter={() => { if (matched) props.onConfirm(); }}
      />
    </Modal>
  );
}