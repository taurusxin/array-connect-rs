import { useId, useState } from "react";
import {
  AlertTriangle,
  Fingerprint,
  LoaderCircle,
  QrCode,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Choice, TextField } from "./fields";
import { command } from "@/lib/api";
import type { Profile, SecretUpdates } from "@/lib/types";
import { useApp } from "@/stores/app";

export function OtpSetup({
  draft,
  setDraft,
  secrets,
  setSecret,
  persist,
}: {
  draft: Profile;
  setDraft: (profile: Profile) => void;
  secrets: SecretUpdates;
  setSecret: (key: keyof SecretUpdates, value: string) => void;
  persist: () => Promise<Profile | null>;
}) {
  const app = useApp();
  const checkboxId = useId();
  const [enrollment, setEnrollment] = useState<Profile | null>(null);
  const [password, setPassword] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [svg, setSvg] = useState<string | null>(null);
  const [loadingQr, setLoadingQr] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const savedSeed = draft.otpSecretStored || Boolean(secrets.otpSecret);
  const openEnrollment = async () => {
    setError(null);
    const profile = await persist();
    if (profile) {
      setEnrollment(profile);
      setConfirmed(false);
      setPassword("");
    }
  };
  const enroll = async (event: React.FormEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (!enrollment || !confirmed) return;
    const input = password;
    setPassword("");
    const profile = await app.enrollOtp(enrollment.id, input, confirmed);
    if (profile) {
      setDraft(profile);
      setEnrollment(null);
      setConfirmed(false);
    } else {
      setError(useApp.getState().error ?? "OTP 注册未完成");
      try {
        await useApp.getState().refresh();
        const current = useApp
          .getState()
          .profiles.find((p) => p.id === enrollment.id);
        if (current) {
          setDraft(current);
          setEnrollment(current);
        }
      } catch {
        /* Keep the explicit enrollment error visible. */
      }
    }
  };
  const showQr = async () => {
    setLoadingQr(true);
    setError(null);
    try {
      const profile = await persist();
      if (!profile) return;
      const result = await command<{ svg: string }>("otp_qr", {
        id: profile.id,
      });
      setSvg(result.svg);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoadingQr(false);
    }
  };
  const clearSeed = () => {
    setSecret("otpSecret", "");
    setDraft({
      ...draft,
      otpSecretStored: false,
      otpPending: false,
      otpParameters: null,
    });
  };
  return (
    <div className="otp-setup">
      <Choice
        label="验证方式"
        value={draft.otpMode}
        onChange={(value) =>
          setDraft({ ...draft, otpMode: value as Profile["otpMode"] })
        }
        options={[
          ["manual", "手动填写密钥"],
          ["automatic", "自动注册"],
        ]}
      />
      {draft.otpMode === "manual" ? (
        <div className="otp-mode-content">
          <TextField
            label="BASE32 密钥（可选）"
            type="password"
            value={secrets.otpSecret ?? ""}
            onChange={(value) => setSecret("otpSecret", value)}
            placeholder={
              draft.otpSecretStored
                ? "已保存密钥 · 留空保留，点击下方按钮可移除"
                : "留空则在登录时手动输入验证码"
            }
            hint="填写密钥后自动生成验证码；使用 SHA-1、6 位，周期和钟差从网关读取。"
          />
          {(draft.otpSecretStored || draft.otpPending) && (
            <Button
              type="button"
              variant="ghost"
              onClick={clearSeed}
              disabled={app.busy}
            >
              <Trash2 />
              移除本地密钥，登录时手动验证
            </Button>
          )}
        </div>
      ) : (
        <div className="otp-mode-content">
          <p className="field-hint">
            使用配置中的用户名和静态密码，在本机随机生成密钥并注册到网关。连接时不会重复注册。
          </p>
          <div className="otp-warning">
            <AlertTriangle size={17} />
            <span>
              如果账号已注册过
              OTP，本次注册会覆盖旧密钥，其他设备上的验证码可能失效。
            </span>
          </div>
          <Button
            type="button"
            variant="outline"
            onClick={() => void openEnrollment()}
            disabled={
              app.busy || loadingQr || app.session.state !== "Disconnected"
            }
          >
            <Fingerprint />
            {draft.otpPending
              ? "重试注册"
              : draft.otpSecretStored
                ? "重新注册 OTP"
                : "注册 OTP"}
          </Button>
          {app.session.state !== "Disconnected" && (
            <p className="field-hint">注册 OTP 前请先断开 VPN。</p>
          )}
        </div>
      )}
      {draft.otpPending && (
        <div className="otp-warning">
          <AlertTriangle size={17} />
          <span>
            上次注册尚未确认。候选密钥已保留，重试会使用同一密钥。移除本地密钥不会撤销网关上的注册。
          </span>
        </div>
      )}
      <div className="otp-actions">
        <Button
          type="button"
          variant="outline"
          onClick={() => void showQr()}
          disabled={app.busy || loadingQr || !savedSeed || draft.otpPending}
        >
          {loadingQr ? <LoaderCircle className="animate-spin" /> : <QrCode />}
          扫码添加到其它验证器
        </Button>
        {draft.otpSecretStored && (
          <span className="field-hint">密钥已存入系统密钥库</span>
        )}
      </div>
      {error && !enrollment && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Dialog
        open={enrollment !== null}
        onOpenChange={(open) => {
          if (!open && !app.busy) {
            setEnrollment(null);
            setPassword("");
            setConfirmed(false);
            setError(null);
          }
        }}
      >
        <DialogContent
          showCloseButton={!app.busy}
          onInteractOutside={(event) => event.preventDefault()}
          onEscapeKeyDown={(event) => {
            if (app.busy) event.preventDefault();
          }}
        >
          <form onSubmit={enroll} className="otp-enrollment-form">
            <DialogHeader>
              <DialogTitle>注册 OTP</DialogTitle>
              <DialogDescription>
                {enrollment?.username} · {enrollment?.server}
              </DialogDescription>
            </DialogHeader>
            <div className="otp-warning">
              <AlertTriangle size={18} />
              <span>
                如果已有注册，网关将覆盖旧密钥。旧验证器中的验证码可能立即失效；此操作无法由本客户端撤销。
              </span>
            </div>
            <TextField
              label="账号静态密码"
              type="password"
              value={password}
              onChange={setPassword}
              autoComplete="current-password"
              placeholder={
                enrollment?.passwordStored
                  ? "留空使用已保存的密码"
                  : "不要追加验证码"
              }
              hint="输入仅用于本次注册，不会自动保存此密码。"
            />
            <div className="flex items-start gap-2">
              <Checkbox
                id={checkboxId}
                checked={confirmed}
                disabled={app.busy}
                onCheckedChange={(value) => setConfirmed(value === true)}
              />
              <Label htmlFor={checkboxId}>
                我确认覆盖该账号已有的 OTP 注册
              </Label>
            </div>
            {app.busy && (
              <p role="status" className="field-hint">
                正在验证网关并注册，请稍候…
              </p>
            )}
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={cancelling}
                onClick={() => {
                  if (app.busy) {
                    setCancelling(true);
                    void command("cancel_otp_enrollment")
                      .catch((cause) => setError(String(cause)))
                      .finally(() => setCancelling(false));
                  } else {
                    setEnrollment(null);
                    setPassword("");
                    setConfirmed(false);
                    setError(null);
                  }
                }}
              >
                {app.busy ? "取消注册" : "取消"}
              </Button>
              <Button
                disabled={
                  app.busy ||
                  !confirmed ||
                  (!password && !enrollment?.passwordStored)
                }
              >
                {app.busy && <LoaderCircle className="animate-spin" />}
                确认注册并覆盖
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog
        open={svg !== null}
        onOpenChange={(open) => {
          if (!open) setSvg(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>添加到其它 TOTP App</DialogTitle>
            <DialogDescription>
              用验证器扫描二维码。二维码包含 OTP 密钥，请勿转发或上传。
            </DialogDescription>
          </DialogHeader>
          {svg && (
            <img
              className="otp-qr"
              src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`}
              alt="OTP 添加二维码"
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
