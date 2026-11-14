import {
  Fingerprint,
  Globe2,
  KeyRound,
  MoreHorizontal,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useApp } from "@/stores/app";
import { host } from "@/lib/format";
import type { Profile } from "@/lib/types";

export function Profiles({
  edit,
  remove,
}: {
  edit: (profile: Profile | null) => void;
  remove: (profile: Profile) => void;
}) {
  const app = useApp();
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
      <div className="profile-grid">
        {app.profiles.map((profile) => {
          const active =
            app.session.state !== "Disconnected" &&
            app.session.profileId === profile.id;
          return (
            <section className="profile-card panel" key={profile.id}>
              <div className="profile-card-heading">
                <span className={`profile-card-icon ${active ? "active" : ""}`}>
                  <Globe2 size={21} />
                </span>
                <Badge variant={active ? "default" : "secondary"}>
                  {active
                    ? "当前连接"
                    : profile.tlsBackend === "openssl"
                      ? "OpenSSL"
                      : "Rustls"}
                </Badge>
              </div>
              <h2>{profile.name}</h2>
              <p className="profile-gateway">{host(profile.server)}</p>
              <dl>
                <div>
                  <dt>用户名</dt>
                  <dd>{profile.username}</dd>
                </div>
                <div>
                  <dt>认证组</dt>
                  <dd>{profile.authgroup || "默认"}</dd>
                </div>
                <div>
                  <dt>路由策略</dt>
                  <dd>
                    {
                      {
                        server: "遵循服务器",
                        full: "IPv4 全隧道",
                        none: "不管理路由",
                      }[profile.routeMode]
                    }
                  </dd>
                </div>
              </dl>
              <div className="profile-features">
                <span>
                  <KeyRound size={12} />
                  {profile.passwordStored ? "密码已保存" : "连接时输入"}
                </span>
                {profile.twoFactor && (
                  <span>
                    <Fingerprint size={12} />
                    {profile.autoTotp ? "自动 2FA" : "手动 2FA"}
                  </span>
                )}
                {profile.proxyEnabled && (
                  <span>
                    <MoreHorizontal size={12} />
                    代理
                  </span>
                )}
              </div>
              <div className="profile-card-actions">
                <Button
                  variant="outline"
                  className="flex-1"
                  onClick={() => app.select(profile.id)}
                  disabled={app.session.state !== "Disconnected" && !active}
                >
                  <ShieldCheck />
                  查看连接
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  title={`编辑 ${profile.name}`}
                  onClick={() => edit(profile)}
                  disabled={active}
                >
                  <Pencil />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  title={`删除 ${profile.name}`}
                  onClick={() => remove(profile)}
                  disabled={active || app.busy}
                >
                  <Trash2 />
                </Button>
              </div>
            </section>
          );
        })}
        <button className="add-profile-card" onClick={() => edit(null)}>
          <span>
            <Plus size={23} />
          </span>
          <strong>添加连接配置</strong>
          <p>准备好你的网关地址和账号</p>
        </button>
      </div>
    </>
  );
}
