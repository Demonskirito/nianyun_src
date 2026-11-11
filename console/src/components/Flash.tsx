export function Flash({ id, flash }: { id: string; flash: { id: string; msg: string; kind?: string } | null }) {
  if (!flash || flash.id !== id || !flash.msg) return null;
  return <p className={"flash" + (flash.kind ? " " + flash.kind : "")}>{flash.msg}</p>;
}
