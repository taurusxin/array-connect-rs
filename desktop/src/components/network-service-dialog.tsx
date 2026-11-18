import { useState } from "react";
import { LoaderCircle, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { networkServiceLabels, type NetworkServiceStatus } from "@/lib/types";
import { useApp } from "@/stores/app";

export function NetworkServiceDialog({
  status,
  onDismiss,
}: {
  status: Exclude<NetworkServiceStatus, "enabled">;
  onDismiss: () => void;
}) {
  const { busy, error, authorizeNetworkService } = useApp();
  const [failed, setFailed] = useState(false);
  const available = status !== "unavailable";

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) onDismiss();
      }}
    >
      <DialogContent
        showCloseButton={!busy}
        onInteractOutside={(event) => event.preventDefault()}
        onEscapeKeyDown={(event) => {
          if (busy) event.preventDefault();
        }}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert size={17} />
            {available ? "需要管理员授权" : "VPN 网络服务不可用"}
          </DialogTitle>
          <DialogDescription>
            {available
              ? "请在 macOS 系统设置的「登录项与扩展」中允许 Array Connect 后台运行。系统要求时，请输入 Mac 管理员密码。批准后回到应用即可连接 VPN。"
              : networkServiceLabels.unavailable}
          </DialogDescription>
        </DialogHeader>
        {failed && error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button
            variant={available ? "outline" : "default"}
            disabled={busy}
            onClick={onDismiss}
          >
            {available ? "稍后" : "知道了"}
          </Button>
          {available && (
            <Button
              disabled={busy}
              onClick={async () => {
                setFailed(false);
                setFailed(!(await authorizeNetworkService()));
              }}
            >
              {busy && <LoaderCircle className="animate-spin" />}
              {status === "notRegistered" ? "继续授权" : "打开系统设置"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
