import {
  Activity,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Clock3,
  Globe2,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Network,
  Pencil,
  Plus,
  Power,
  Shield,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RateChart } from "@/components/rate-chart";
import { Choice } from "@/components/fields";
import { useApp } from "@/stores/app";
import { bytes, date, duration, host } from "@/lib/format";
import { emptySession, stateLabels, type Profile } from "@/lib/types";

export function Overview({
  edit,
  connect,
}: {
  edit: (profile: Profile | null) => void;
  connect: () => void;
}) {
  const app = useApp();
  const profile = app.profiles.find(
    (p) =>
      p.id ===
      (app.session.state !== "Disconnected"
        ? app.session.profileId
        : app.selectedId),
  );
  const active = app.session.state !== "Disconnected";
  const live =
    app.session.profileId === profile?.id ? app.session : emptySession;
  const connected = app.session.state === "Connected";
  const transitioning = active && !connected;
  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">YOUR SECURE WORKSPACE</div>
          <h1>连接概览</h1>
          <p>连接你的网络，让工作顺畅进行。</p>
        </div>
        <div className="overview-header-actions">
          {app.profiles.length > 0 && (
            <div
              className="overview-profile-picker"
              title={active ? "断开连接后可切换配置" : undefined}
            >
              <Choice
                label="当前配置"
                value={profile?.id ?? ""}
                onChange={app.select}
                disabled={active || app.busy}
                options={app.profiles.map((p) => [
                  p.id,
                  `${p.name} · ${host(p.server)}`,
                ])}
              />
            </div>
          )}
          <Button variant="outline" onClick={() => edit(null)}>
            <Plus />
            新建配置
          </Button>
        </div>
      </header>
      {!profile ? (
        <section className="empty-welcome panel">
          <div className="welcome-icon">
            <ShieldCheck size={38} strokeWidth={1.6} />
          </div>
          <Badge variant="secondary">Array Networks SSL VPN</Badge>
          <h2>从一个安全连接开始</h2>
          <p>
            添加网关与账号，轻松访问你的内网资源。
            <br />
            凭据由本机系统密钥库妥善保管。
          </p>
          <Button size="lg" onClick={() => edit(null)}>
            <Plus />
            添加第一个配置
            <ArrowRight />
          </Button>
          <div className="welcome-features">
            <span>
              <LockKeyhole />
              系统密钥库
            </span>
            <span>
              <KeyRound />
              自动两步认证
            </span>
            <span>
              <Activity />
              实时网络统计
            </span>
          </div>
        </section>
      ) : (
        <>
          <section
            className={`connection-panel panel ${connected ? "is-connected" : ""}`}
          >
            <div className="connection-main">
              <div className={`connection-emblem ${connected ? "secure" : ""}`}>
                {transitioning ? (
                  <LoaderCircle size={28} className="animate-spin" />
                ) : connected ? (
                  <ShieldCheck size={30} strokeWidth={1.7} />
                ) : (
                  <Shield size={30} strokeWidth={1.7} />
                )}
              </div>
              <div className="connection-text">
                <div className="connection-title">
                  <h2>{profile.name}</h2>
                  <Badge
                    variant="outline"
                    className={connected ? "connected-badge" : "neutral-badge"}
                  >
                    <span
                      className={
                        connected ? "status-dot connected" : "status-dot"
                      }
                    />
                    {stateLabels[app.session.state] ?? app.session.state}
                  </Badge>
                </div>
                <p>
                  <Globe2 size={13} />
                  {host(profile.server)}
                  <span className="dot-separator">·</span>
                  {profile.username}
                </p>
              </div>
              <Button
                variant="ghost"
                size="icon-sm"
                title="编辑配置"
                disabled={active}
                onClick={() => edit(profile)}
              >
                <Pencil size={15} />
              </Button>
            </div>
            <div className="connection-action">
              <span>
                {connected
                  ? "你的连接已受到保护"
                  : transitioning
                    ? "正在处理连接，请稍候"
                    : "准备好连接你的网络"}
              </span>
              <Button
                size="lg"
                className={active ? "disconnect-button" : "connect-button"}
                variant={active ? "outline" : "default"}
                disabled={app.busy}
                onClick={active ? () => void app.disconnect() : connect}
              >
                {app.busy ? (
                  <LoaderCircle className="animate-spin" />
                ) : (
                  <Power />
                )}
                {active
                  ? transitioning
                    ? "取消连接"
                    : "断开连接"
                  : "连接 VPN"}
              </Button>
            </div>
          </section>
          {live.error && !active && (
            <div className="connection-error" role="alert">
              <Shield size={15} />
              <div>
                <strong>连接已结束</strong>
                <p>{live.error}</p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => app.setPage("logs")}
              >
                查看日志
                <ArrowRight />
              </Button>
            </div>
          )}
          <div className="stats-grid">
            <Stat
              icon={<Clock3 />}
              label="连接时长"
              value={duration(live.connectedSeconds)}
              hint="当前会话"
            />
            <Stat
              icon={<ArrowDown />}
              label="已下载"
              value={bytes(live.stats.bytes_received)}
              hint="本次接收流量"
            />
            <Stat
              icon={<ArrowUp />}
              label="已上传"
              value={bytes(live.stats.bytes_sent)}
              hint="本次发送流量"
            />
            <Stat
              icon={<Network />}
              label="内网 IP"
              value={active ? (live.network?.address ?? "—") : "—"}
              hint={
                active && live.network
                  ? `MTU ${live.network.mtu}`
                  : "连接后自动分配"
              }
            />
          </div>
          <RateChart
            samples={app.session.profileId === profile.id ? app.samples : []}
            download={live.downloadRate}
            upload={live.uploadRate}
            connected={connected}
          />
        </>
      )}
      <section className="panel history-panel">
        <div className="panel-heading">
          <div>
            <h2>最近连接</h2>
            <p>
              累计 {app.usage.sessions} 次连接 · 下载{" "}
              {bytes(app.usage.bytesReceived)} · 上传{" "}
              {bytes(app.usage.bytesSent)}
            </p>
          </div>
          <Badge variant="secondary">本机记录</Badge>
        </div>
        {app.usage.recent.length ? (
          <div className="history-table">
            <table>
              <thead>
                <tr>
                  <th>连接配置</th>
                  <th>连接时间</th>
                  <th>时长</th>
                  <th>总流量</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {app.usage.recent.slice(0, 5).map((item) => (
                  <tr key={item.id}>
                    <td>
                      <span className="table-profile">
                        <span className="tiny-icon">
                          <Globe2 size={14} />
                        </span>
                        <span>
                          {item.profileName}
                          <small>{host(item.server)}</small>
                        </span>
                      </span>
                    </td>
                    <td>{date(item.startedAt)}</td>
                    <td className="tabular">
                      {duration(item.connectedSeconds)}
                    </td>
                    <td className="tabular">
                      {bytes(item.bytesReceived + item.bytesSent)}
                    </td>
                    <td>
                      <span className="history-state">
                        <span
                          className={
                            item.endedAt === null
                              ? "status-dot connected"
                              : "status-dot"
                          }
                        />
                        {item.state === "failed"
                          ? "连接失败"
                          : item.state === "interrupted"
                            ? "意外中断"
                            : item.endedAt === null
                              ? "连接中"
                              : "已结束"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="history-empty">
            <Clock3 size={18} />
            <span>还没有连接记录，完成首次连接后会显示在这里。</span>
          </div>
        )}
      </section>
    </>
  );
}
function Stat({
  icon,
  label,
  value,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className="stat-card panel">
      <div className="stat-top">
        <span>{label}</span>
        {icon}
      </div>
      <strong>{value}</strong>
      <small>{hint}</small>
    </div>
  );
}
