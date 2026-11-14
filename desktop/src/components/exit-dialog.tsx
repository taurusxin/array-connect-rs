import { useEffect, useId, useState } from "react";
import { LoaderCircle, LogOut, PanelBottomClose } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import type { CloseChoice } from "@/lib/types";
import { useApp } from "@/stores/app";

export function ExitDialog() {
  const app = useApp();
  const rememberId = useId();
  const [remember, setRemember] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [failed, setFailed] = useState(false);
  const choosing = app.exitState === "choose";
  const closing = app.exitState === "closing";
  const checking = app.exitState === "checking";
  const waiting = closing || checking || submitting;
  const active = app.session.state !== "Disconnected";
  useEffect(() => {
    if (app.exitState === "choose") {
      setRemember(false);
      setFailed(false);
    }
  }, [app.exitState]);
  const choose = async (choice: CloseChoice) => {
    setSubmitting(true);
    setFailed(false);
    const success = await app.chooseClose(choice, remember);
    setFailed(!success);
    setSubmitting(false);
  };
  return (
    <Dialog
      open={app.exitState !== "idle"}
      onOpenChange={(open) => {
        if (!open && !waiting) void app.cancelExit();
      }}
    >
      <DialogContent
        showCloseButton={!waiting}
        onInteractOutside={(event) => event.preventDefault()}
        onEscapeKeyDown={(event) => {
          if (waiting) event.preventDefault();
        }}
      >
        <DialogHeader>
          <div className="dialog-eyebrow">
            {waiting ? (
              <LoaderCircle size={16} className="animate-spin" />
            ) : choosing ? (
              <PanelBottomClose size={16} />
            ) : (
              <LogOut size={16} />
            )}
            {closing ? "正在安全退出" : choosing ? "关闭窗口" : "退出客户端"}
          </div>
          <DialogTitle>
            {closing
              ? "正在清理连接…"
              : checking
                ? "正在处理关闭请求…"
                : choosing
                  ? "如何关闭 Array Connect？"
                  : active
                    ? "断开连接并退出？"
                    : "退出 Array Connect？"}
          </DialogTitle>
          <DialogDescription>
            {closing
              ? "正在等待 VPN 断开及网络清理完成，请稍候。"
              : checking
                ? "请稍候。"
                : choosing
                  ? "最小化到托盘后会继续在后台运行，并保持 VPN 连接。"
                  : active
                    ? "退出应用会断开当前 VPN 连接，是否继续？"
                    : "VPN 连接已结束，是否继续退出？"}
          </DialogDescription>
        </DialogHeader>
        {choosing && (
          <>
            <div className="flex items-center gap-2 py-1">
              <Checkbox
                id={rememberId}
                checked={remember}
                disabled={waiting}
                onCheckedChange={(checked) => setRemember(checked === true)}
              />
              <Label htmlFor={rememberId}>不再询问，记住本次选择</Label>
            </div>
            {!app.trayAvailable && (
              <p className="text-sm text-muted-foreground">
                当前系统托盘不可用，可以取消关闭或退出应用。
              </p>
            )}
            {failed && (
              <p role="alert" className="text-sm text-destructive">
                {app.error}
              </p>
            )}
          </>
        )}
        {!closing && !checking && (
          <DialogFooter>
            {choosing ? (
              <>
                <Button
                  variant="outline"
                  disabled={waiting}
                  onClick={() => void choose("exit")}
                >
                  <LogOut />
                  退出程序
                </Button>
                <Button
                  disabled={waiting || !app.trayAvailable}
                  onClick={() => void choose("tray")}
                >
                  <PanelBottomClose />
                  最小化到托盘
                </Button>
              </>
            ) : (
              <>
                <Button variant="outline" onClick={() => void app.cancelExit()}>
                  取消
                </Button>
                <Button onClick={() => void app.confirmExit()}>
                  <LogOut />
                  {active ? "断开并退出" : "退出程序"}
                </Button>
              </>
            )}
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  );
}
