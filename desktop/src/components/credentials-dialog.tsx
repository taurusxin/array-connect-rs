import { useState } from "react";
import { Fingerprint, KeyRound, LoaderCircle, ShieldCheck } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { TextField } from "./fields";
import { useApp } from "@/stores/app";
import type { CredentialRequest } from "@/lib/types";

export function CredentialsDialog({ request }: { request: CredentialRequest }) {
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [pending, setPending] = useState(false);
  const profile = useApp((s) =>
    s.profiles.find((p) => p.id === request.profileId),
  );
  const submit = useApp((s) => s.submit);
  const disconnect = useApp((s) => s.disconnect);
  const cancel = () => {
    setPassword("");
    setOtp("");
    void disconnect();
  };
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) cancel();
      }}
    >
      <DialogContent
        className="credential-dialog"
        onInteractOutside={(e) => e.preventDefault()}
      >
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setPending(true);
            await submit(password, otp);
            setPassword("");
            setOtp("");
            setPending(false);
          }}
        >
          <DialogHeader>
            <div className="dialog-eyebrow">
              <ShieldCheck size={15} />
              TLS 握手已完成
            </div>
            <DialogTitle>完成身份认证</DialogTitle>
            <DialogDescription>
              {profile?.name ?? "当前连接"} · {profile?.username}
            </DialogDescription>
          </DialogHeader>
          <div className="credentials-fields">
            {request.needsPassword && (
              <TextField
                label="登录密码"
                type="password"
                value={password}
                onChange={setPassword}
                autoComplete="current-password"
                placeholder="输入密码"
              />
            )}
            {request.needsOtp && (
              <TextField
                label="两步验证码"
                value={otp}
                onChange={setOtp}
                placeholder={`输入 ${profile?.totpDigits ?? 6} 位验证码`}
                autoComplete="one-time-code"
              />
            )}
            <div className="inline-note">
              {request.needsOtp ? (
                <Fingerprint size={16} />
              ) : (
                <KeyRound size={16} />
              )}
              <span>
                {request.needsOtp
                  ? "验证码将直接追加到密码后，仅用于本次认证。"
                  : profile?.savePassword
                    ? "已启用保存密码，本次输入将存入系统密钥库。"
                    : "密码仅保留在当前会话内存中。"}
              </span>
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={cancel}
              disabled={pending}
            >
              取消连接
            </Button>
            <Button
              disabled={
                pending ||
                (request.needsPassword && !password) ||
                (request.needsOtp && otp.length !== (profile?.totpDigits ?? 6))
              }
            >
              {pending && <LoaderCircle className="animate-spin" />}认证
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
