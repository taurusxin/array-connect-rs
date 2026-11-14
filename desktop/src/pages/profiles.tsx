import {
  Fingerprint,
  Globe2,
  KeyRound,
  Network,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useApp } from "@/stores/app";
import { host } from "@/lib/format";
import { stateLabels, type Profile } from "@/lib/types";

export function Profiles({
  edit,
  remove,
}: {
  edit: (profile: Profile | null) => void;
  remove: (profile: Profile) => void;
}) {
  const app = useApp();
  const running = app.session.state !== "Disconnected";
  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">CONNECTION PROFILES</div>
          <h1>连接配置</h1>
          <p>多个网络，一处管理。每次仅连接一个配置。</p>
        </div>
        <Button onClick={() => edit(null)}>
          <Plus />
          新建配置
        </Button>
      </header>
      <section className="panel profiles-list">
        <div className="profiles-list-heading">
          <strong>
            我的配置 <span>{app.profiles.length}</span>
          </strong>
          <span>在首页下拉选择要连接的网络</span>
        </div>
        {app.profiles.length > 0 ? (
          <div className="profiles-table-scroll">
            <table className="profiles-table">
              <colgroup>
                <col style={{ width: "30%" }} />
                <col style={{ width: "20%" }} />
                <col style={{ width: "18%" }} />
                <col style={{ width: "14%" }} />
                <col style={{ width: "18%" }} />
              </colgroup>
              <thead>
                <tr>
                  <th>名称 / 网关</th>
                  <th>用户 / 认证组</th>
                  <th>安全与代理</th>
                  <th>路由策略</th>
                  <th className="profiles-actions-heading">操作</th>
                </tr>
              </thead>
              <tbody>
                {app.profiles.map((profile) => {
                  const active =
                    running && app.session.profileId === profile.id;
                  const selected = app.selectedId === profile.id;
                  return (
                    <tr
                      key={profile.id}
                      className={selected ? "selected-profile-row" : ""}
                    >
                      <td>
                        <div className="profile-row-name">
                          <span
                            className={
                              active
                                ? "profile-row-icon active"
                                : "profile-row-icon"
                            }
                          >
                            <Globe2 size={17} />
                          </span>
                          <div>
                            <div className="profile-row-title">
                              <strong title={profile.name}>
                                {profile.name}
                              </strong>
                              {active && (
                                <Badge
                                  variant="outline"
                                  className="connected-badge"
                                >
                                  {stateLabels[app.session.state] ?? "当前会话"}
                                </Badge>
                              )}
                            </div>
                            <small title={profile.server}>
                              {host(profile.server)}
                            </small>
                          </div>
                        </div>
                      </td>
                      <td>
                        <div className="profile-row-account">
                          <span title={profile.username}>
                            {profile.username}
                          </span>
                          <small title={profile.authgroup}>
                            {profile.authgroup || "默认认证组"}
                          </small>
                        </div>
                      </td>
                      <td>
                        <div className="profile-row-features">
                          <Badge variant="secondary">
                            {profile.tlsBackend === "openssl"
                              ? "OpenSSL"
                              : "Rustls"}
                          </Badge>
                          {profile.twoFactor && (
                            <span
                              title={
                                profile.autoTotp
                                  ? "自动两步认证"
                                  : "手动两步认证"
                              }
                            >
                              <Fingerprint size={13} />
                              2FA
                            </span>
                          )}
                          {profile.proxyEnabled && (
                            <span
                              title={`${profile.proxyScheme.toUpperCase()} 代理`}
                            >
                              <Network size={13} />
                            </span>
                          )}
                        </div>
                        <small className="profile-row-vault">
                          <KeyRound size={11} />
                          {profile.passwordStored
                            ? "密码已保存"
                            : "连接时输入密码"}
                        </small>
                      </td>
                      <td>
                        <span className="profile-route-label">
                          {
                            {
                              server: "遵循服务器",
                              full: "IPv4 全隧道",
                              none: "不管理路由",
                            }[profile.routeMode]
                          }
                        </span>
                      </td>
                      <td>
                        <div className="profile-row-actions">
                          <Button
                            variant={selected ? "secondary" : "outline"}
                            size="sm"
                            onClick={() => app.select(profile.id)}
                            disabled={running && !active}
                          >
                            {selected ? "查看" : "使用"}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={`编辑 ${profile.name}`}
                            title={`编辑 ${profile.name}`}
                            onClick={() => edit(profile)}
                            disabled={active}
                          >
                            <Pencil />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={`删除 ${profile.name}`}
                            title={`删除 ${profile.name}`}
                            onClick={() => remove(profile)}
                            disabled={active || app.busy}
                          >
                            <Trash2 />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="profiles-list-empty">
            <Globe2 size={30} strokeWidth={1.4} />
            <h2>还没有连接配置</h2>
            <p>填写网关地址和账号，添加你的第一个安全连接。</p>
            <Button variant="outline" onClick={() => edit(null)}>
              <Plus />
              添加配置
            </Button>
          </div>
        )}
        <footer className="profiles-list-footer">
          <ShieldCheck size={13} />
          凭据由系统密钥库保护。连接期间可编辑其它配置，当前配置需断开后编辑。
        </footer>
      </section>
    </>
  );
}
