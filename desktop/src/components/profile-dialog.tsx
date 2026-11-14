import { useState } from "react";
import {
  Fingerprint,
  Globe2,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Network,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { TextField, Choice, ToggleRow } from "./fields";
import { newProfile, type Profile, type SecretUpdates } from "@/lib/types";
import { useApp } from "@/stores/app";

function Lines({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string[];
  onChange: (value: string[]) => void;
  placeholder: string;
}) {
  return (
    <div className="field">
      <Label>{label}</Label>
      <Textarea
        aria-label={label}
        value={value.join("\n")}
        onChange={(e) => onChange(e.target.value.split("\n"))}
        placeholder={placeholder}
        rows={3}
        spellCheck={false}
      />
      <p className="field-hint">每行一项</p>
    </div>
  );
}
export function ProfileDialog({
  profile,
  onClose,
}: {
  profile: Profile | null;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<Profile>(() =>
    profile ? { ...profile } : newProfile(),
  );
  const [secrets, setSecrets] = useState<SecretUpdates>({});
  const save = useApp((s) => s.saveProfile);
  const busy = useApp((s) => s.busy);
  const update = <K extends keyof Profile>(key: K, value: Profile[K]) =>
    setDraft((old) => ({ ...old, [key]: value }));
  const secret = (key: keyof SecretUpdates, value: string) =>
    setSecrets((old) => ({ ...old, [key]: value }));
  const close = () => {
    setSecrets({});
    onClose();
  };
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const clean = {
      ...draft,
      name: draft.name.trim(),
      server: draft.server.trim(),
      username: draft.username.trim(),
      serverPins: draft.serverPins.map((s) => s.trim()).filter(Boolean),
      includeRoutes: draft.includeRoutes.map((s) => s.trim()).filter(Boolean),
      excludeRoutes: draft.excludeRoutes.map((s) => s.trim()).filter(Boolean),
    };
    if (await save(clean, secrets)) close();
  };
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) close();
      }}
    >
      <DialogContent
        className="profile-dialog"
        onInteractOutside={(event) => event.preventDefault()}
      >
        <form onSubmit={submit}>
          <DialogHeader>
            <div className="dialog-eyebrow">
              <ShieldCheck size={15} />
              连接配置
            </div>
            <DialogTitle>
              {profile ? "编辑连接配置" : "添加一个安全连接"}
            </DialogTitle>
            <DialogDescription>
              配置保存在本机。密码和 2FA 密钥由系统密钥库保护。
            </DialogDescription>
          </DialogHeader>
          <Tabs defaultValue="general" className="profile-tabs">
            <TabsList className="w-full">
              <TabsTrigger value="general">
                <Globe2 />
                基本
              </TabsTrigger>
              <TabsTrigger value="auth">
                <Fingerprint />
                认证
              </TabsTrigger>
              <TabsTrigger value="network">
                <Network />
                网络
              </TabsTrigger>
              <TabsTrigger value="advanced">
                <SlidersHorizontal />
                高级
              </TabsTrigger>
            </TabsList>
            <div className="profile-form-scroll">
              <TabsContent value="general">
                <div className="form-grid">
                  <TextField
                    label="配置名称"
                    value={draft.name}
                    onChange={(v) => update("name", v)}
                    placeholder="例如：公司网络"
                  />
                  <TextField
                    label="网关地址"
                    value={draft.server}
                    onChange={(v) => update("server", v)}
                    placeholder="https://vpn.example.com:443"
                  />
                  <TextField
                    label="用户名"
                    value={draft.username}
                    onChange={(v) => update("username", v)}
                    autoComplete="username"
                    placeholder="你的登录账号"
                  />
                  <TextField
                    label="认证组"
                    value={draft.authgroup}
                    onChange={(v) => update("authgroup", v)}
                    placeholder="与网关配置一致，如 local"
                  />
                </div>
                <div className="form-section">
                  <h3>
                    <KeyRound size={15} />
                    登录凭据
                  </h3>
                  <ToggleRow
                    label="保存密码"
                    hint="使用 Windows 凭据管理器 / macOS 钥匙串 / Linux Secret Service"
                    checked={draft.savePassword}
                    onChange={(v) => update("savePassword", v)}
                  />
                  {draft.savePassword && (
                    <TextField
                      label="密码"
                      type="password"
                      value={secrets.password ?? ""}
                      onChange={(v) => secret("password", v)}
                      autoComplete="new-password"
                      placeholder={
                        draft.passwordStored
                          ? "已保存 · 留空保持现有密码"
                          : "可以稍后在 TLS 握手成功后输入"
                      }
                    />
                  )}
                </div>
              </TabsContent>
              <TabsContent value="auth">
                <div className="form-section first">
                  <ToggleRow
                    icon={<Fingerprint size={19} />}
                    label="启用两步验证（2FA）"
                    hint="认证时将验证码直接追加到密码末尾，不添加分隔符。"
                    checked={draft.twoFactor}
                    onChange={(v) => update("twoFactor", v)}
                  />
                  {draft.twoFactor && (
                    <>
                      <TextField
                        label="BASE32 密钥"
                        type="password"
                        value={secrets.totpSecret ?? ""}
                        onChange={(v) => secret("totpSecret", v)}
                        placeholder={
                          draft.totpStored
                            ? "已存入系统密钥库 · 留空保持"
                            : "输入验证器提供的 BASE32 密钥"
                        }
                        hint="不会把密钥或生成的验证码写入 SQLite、日志或浏览器存储。"
                      />
                      <ToggleRow
                        label="自动认证"
                        hint="每次认证生成新的 TOTP 验证码；关闭后手动输入验证码。"
                        checked={draft.autoTotp}
                        onChange={(v) => update("autoTotp", v)}
                      />
                      <div className="form-grid">
                        <Choice
                          label="算法"
                          value={draft.totpAlgorithm}
                          onChange={(v) => update("totpAlgorithm", v)}
                          options={[
                            ["SHA1", "SHA-1（常用）"],
                            ["SHA256", "SHA-256"],
                            ["SHA512", "SHA-512"],
                          ]}
                        />
                        <Choice
                          label="验证码位数"
                          value={String(draft.totpDigits)}
                          onChange={(v) => update("totpDigits", Number(v))}
                          options={[
                            ["6", "6 位"],
                            ["8", "8 位"],
                          ]}
                        />
                        <TextField
                          label="更新周期（秒）"
                          type="number"
                          value={draft.totpPeriod}
                          onChange={(v) => update("totpPeriod", Number(v))}
                          hint="默认 30 秒，请保持系统时间准确。"
                        />
                      </div>
                    </>
                  )}
                </div>
                <div className="inline-note">
                  <LockKeyhole size={16} />
                  <span>
                    未保存密码时，客户端会在 TLS
                    握手及证书验证通过后请求输入密码。
                  </span>
                </div>
              </TabsContent>
              <TabsContent value="network">
                <div className="form-section first">
                  <ToggleRow
                    label="通过代理连接"
                    hint="支持 HTTP CONNECT 和 SOCKS5，代理密码存入系统密钥库。"
                    checked={draft.proxyEnabled}
                    onChange={(v) => update("proxyEnabled", v)}
                  />
                  {draft.proxyEnabled && (
                    <div className="form-grid">
                      <Choice
                        label="代理协议"
                        value={draft.proxyScheme}
                        onChange={(v) => update("proxyScheme", v)}
                        options={[
                          ["http", "HTTP CONNECT"],
                          ["socks5", "SOCKS5"],
                        ]}
                      />
                      <TextField
                        label="代理地址"
                        value={draft.proxyHost}
                        onChange={(v) => update("proxyHost", v)}
                        placeholder="127.0.0.1"
                      />
                      <TextField
                        label="代理端口"
                        type="number"
                        value={draft.proxyPort}
                        onChange={(v) => update("proxyPort", Number(v))}
                      />
                      <TextField
                        label="代理用户名（可选）"
                        value={draft.proxyUsername}
                        onChange={(v) => update("proxyUsername", v)}
                      />
                      <TextField
                        label="代理密码（可选）"
                        type="password"
                        value={secrets.proxyPassword ?? ""}
                        onChange={(v) => secret("proxyPassword", v)}
                        placeholder={
                          draft.proxyPasswordStored
                            ? "已保存 · 留空保持"
                            : "不保存到配置数据库"
                        }
                      />
                    </div>
                  )}
                </div>
                <div className="form-section">
                  <h3>路由与网卡</h3>
                  <div className="form-grid">
                    <Choice
                      label="路由模式"
                      value={draft.routeMode}
                      onChange={(v) =>
                        update("routeMode", v as Profile["routeMode"])
                      }
                      options={[
                        ["server", "遵循服务器"],
                        ["full", "IPv4 全隧道"],
                        ["none", "不管理路由"],
                      ]}
                    />
                    <TextField
                      label="MTU"
                      type="number"
                      value={draft.mtu}
                      onChange={(v) => update("mtu", Number(v))}
                    />
                    <TextField
                      label="网卡名称（可选）"
                      value={draft.interfaceName}
                      onChange={(v) => update("interfaceName", v)}
                      placeholder="留空自动分配"
                    />
                    <TextField
                      label="指定解析 IP（可选）"
                      value={draft.resolve}
                      onChange={(v) => update("resolve", v)}
                      placeholder="保持原始域名用于 SNI"
                    />
                    <Lines
                      label="附加包含路由"
                      value={draft.includeRoutes}
                      onChange={(v) => update("includeRoutes", v)}
                      placeholder="10.0.0.0/8"
                    />
                    <Lines
                      label="附加排除路由"
                      value={draft.excludeRoutes}
                      onChange={(v) => update("excludeRoutes", v)}
                      placeholder="192.168.1.0/24"
                    />
                  </div>
                  <ToggleRow
                    label="管理 DNS"
                    hint="使用服务器下发的 DNS 和搜索域，断开时恢复。"
                    checked={draft.manageDns}
                    onChange={(v) => update("manageDns", v)}
                  />
                </div>
              </TabsContent>
              <TabsContent value="advanced">
                <div className="form-grid">
                  <Choice
                    label="TLS 后端"
                    value={draft.tlsBackend}
                    onChange={(v) =>
                      setDraft((old) => ({
                        ...old,
                        tlsBackend: v as Profile["tlsBackend"],
                        opensslCiphers:
                          v === "rustls" ? "" : old.opensslCiphers,
                      }))
                    }
                    options={[
                      ["rustls", "Rustls（默认）"],
                      ["openssl", "OpenSSL（旧网关兼容）"],
                    ]}
                  />
                  <TextField
                    label="额外 CA 文件（可选）"
                    value={draft.caFile}
                    onChange={(v) => update("caFile", v)}
                    placeholder="本机 PEM 文件绝对路径"
                  />
                  {draft.tlsBackend === "openssl" && (
                    <TextField
                      label="OpenSSL 密码套件（可选）"
                      value={draft.opensslCiphers}
                      onChange={(v) => update("opensslCiphers", v)}
                      placeholder="DEFAULT 或 AES128-SHA"
                    />
                  )}
                  <Lines
                    label="服务器公钥指纹（可选）"
                    value={draft.serverPins}
                    onChange={(v) => update("serverPins", v)}
                    placeholder="pin-sha256:BASE64_SHA256_SPKI"
                  />
                </div>
                <ToggleRow
                  label="跳过证书 CA / 域名校验"
                  hint="仅在明确了解风险时开启。不能与公钥固定同时使用。"
                  checked={draft.insecure}
                  onChange={(v) => update("insecure", v)}
                />
                <div className="form-section">
                  <h3>连接行为</h3>
                  <div className="form-grid">
                    <TextField
                      label="连接超时（秒）"
                      type="number"
                      value={draft.connectTimeout}
                      onChange={(v) => update("connectTimeout", Number(v))}
                    />
                    <TextField
                      label="重连窗口（秒）"
                      type="number"
                      value={draft.reconnectTimeout}
                      onChange={(v) => update("reconnectTimeout", Number(v))}
                      hint="设置 0 关闭自动重连"
                    />
                    <TextField
                      label="DPD 间隔（秒，可选）"
                      type="number"
                      value={draft.dpd ?? ""}
                      onChange={(v) => update("dpd", v ? Number(v) : null)}
                      placeholder="遵循服务器，或默认 30"
                    />
                    <TextField
                      label="客户端 hostname（可选）"
                      value={draft.hostname}
                      onChange={(v) => update("hostname", v)}
                      placeholder="默认使用本机名称"
                    />
                    <TextField
                      label="User-Agent（可选）"
                      value={draft.userAgent}
                      onChange={(v) => update("userAgent", v)}
                      placeholder="arraysslvpn/0.1.0"
                    />
                  </div>
                </div>
              </TabsContent>
            </div>
          </Tabs>
          <DialogFooter>
            <p className="dialog-footer-note">
              <LockKeyhole size={13} />
              凭据始终留在本机
            </p>
            <Button
              type="button"
              variant="outline"
              onClick={close}
              disabled={busy}
            >
              取消
            </Button>
            <Button type="submit" disabled={busy}>
              {busy && <LoaderCircle className="animate-spin" />}保存配置
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
