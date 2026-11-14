import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDownToLine,
  Check,
  Copy,
  ListFilter,
  Pause,
  Play,
  Search,
  Terminal,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Choice } from "@/components/fields";
import { useApp } from "@/stores/app";
import type { LogRecord } from "@/lib/types";

const ranks: Record<string, number> = {
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
  trace: 5,
};
export function Logs() {
  const app = useApp();
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState("trace");
  const [paused, setPaused] = useState<LogRecord[] | null>(null);
  const [follow, setFollow] = useState(true);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");
  const bottom = useRef<HTMLDivElement>(null);
  const logs = paused ?? app.logs;
  const filtered = useMemo(
    () =>
      logs.filter(
        (log) =>
          ranks[log.level] <= ranks[level] &&
          `${log.message} ${log.target}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [logs, level, search],
  );
  useEffect(() => {
    if (follow && !paused)
      bottom.current?.scrollIntoView({ behavior: "instant", block: "end" });
  }, [filtered.length, paused, follow]);
  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">LIVE DIAGNOSTICS</div>
          <h1>实时日志</h1>
          <p>查看连接的每个阶段，快速定位问题。</p>
        </div>
        <div className="header-actions">
          <Button
            variant="outline"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(
                  filtered
                    .map(
                      (log) =>
                        `${new Date(log.timestamp).toISOString()} ${log.level.toUpperCase()} ${log.target} ${log.message}`,
                    )
                    .join("\n"),
                );
                setCopied(true);
                setTimeout(() => setCopied(false), 1800);
              } catch {
                setCopyError("无法访问剪贴板，请检查系统权限。");
              }
            }}
          >
            {copied ? <Check /> : <Copy />}
            {copied ? "已复制" : "复制日志"}
          </Button>
          <Button
            variant="outline"
            size="icon"
            title="清空日志"
            onClick={() => {
              setPaused(null);
              void app.clearLogs();
            }}
          >
            <Trash2 />
          </Button>
        </div>
      </header>
      <section className="panel log-panel">
        <div className="log-toolbar">
          <div className="log-search">
            <Search size={14} />
            <Input
              aria-label="搜索日志"
              placeholder="搜索消息或模块…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="log-filters">
            <ListFilter size={14} />
            <Choice
              label="显示等级"
              value={level}
              onChange={setLevel}
              options={[
                ["trace", "全部等级"],
                ["debug", "Debug 及以上"],
                ["info", "Info 及以上"],
                ["warn", "Warn 及以上"],
                ["error", "仅 Error"],
              ]}
            />
            <Button
              variant={paused ? "secondary" : "ghost"}
              size="icon"
              title={paused ? "继续滚动" : "暂停显示"}
              onClick={() => setPaused(paused ? null : [...app.logs])}
            >
              {paused ? <Play /> : <Pause />}
            </Button>
            <Button
              variant={follow ? "secondary" : "ghost"}
              size="icon"
              title="跟随最新日志"
              onClick={() => setFollow(!follow)}
            >
              <ArrowDownToLine />
            </Button>
          </div>
        </div>
        <div className="log-body" role="log" aria-label="VPN 实时日志">
          {filtered.length ? (
            filtered.map((log) => (
              <div className="log-line" key={log.id}>
                <time>
                  {new Date(log.timestamp).toLocaleTimeString("zh-CN", {
                    hour12: false,
                  })}
                  .{String(log.timestamp % 1000).padStart(3, "0")}
                </time>
                <span className={`log-level ${log.level}`}>
                  {log.level.toUpperCase()}
                </span>
                <div>
                  <span className="log-target">
                    {log.target.replace("arraysslvpn::", "")}
                  </span>
                  <span className="log-message">{log.message}</span>
                </div>
              </div>
            ))
          ) : (
            <div className="logs-empty">
              <Terminal size={28} strokeWidth={1.5} />
              <h3>{search ? "没有匹配的日志" : "等待连接活动"}</h3>
              <p>
                {search
                  ? "尝试调整搜索关键词或等级筛选。"
                  : "开始连接后，解析、TLS、认证与隧道日志会实时显示。"}
              </p>
            </div>
          )}
          <div ref={bottom} />
        </div>
        <footer className="log-footer">
          <span>
            <span className="status-dot connected" />
            {paused ? "显示已暂停，后台仍在接收" : "实时接收"} ·{" "}
            {filtered.length} 条
          </span>
          <span>
            采集等级 {app.preferences.logLevel.toUpperCase()} · 最多保留 2,000
            条
          </span>
        </footer>
      </section>
      {copyError && <p className="text-destructive text-xs">{copyError}</p>}
      <div className="page-footnote">
        <ShieldNote />
        密码、Cookie 和验证码已脱敏。分享日志前，请按需隐藏网关地址和内网信息。
      </div>
    </>
  );
}
function ShieldNote() {
  return <Check size={13} />;
}
