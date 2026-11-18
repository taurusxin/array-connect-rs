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

const serviceActions = {
  notInstalled: "安装网络服务",
  upgradeRequired: "更新网络服务",
  repairRequired: "重新安装网络服务",
};

export function NetworkServiceDialog({
  status,
  onDismiss,
}: {
  status: Exclude<NetworkServiceStatus, "enabled">;
  onDismiss: () => void;
}) {
  const { busy, error, installNetworkService } = useApp();
  const [failed, setFailed] = useState(false);
  const action = status === "unavailable" ? null : serviceActions[status];

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
            {action ?? "VPN 网络服务不可用"}
          </DialogTitle>
          <DialogDescription>
            {networkServiceLabels[status]}
            {action &&
              "请在 macOS 弹出的系统窗口中完成管理员认证。服务就绪后可直接连接 VPN。"}
          </DialogDescription>
        </DialogHeader>
        {failed && error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button
            variant={action ? "outline" : "default"}
            disabled={busy}
            onClick={onDismiss}
          >
            {action ? "稍后" : "知道了"}
          </Button>
          {action && (
            <Button
              disabled={busy}
              onClick={async () => {
                setFailed(false);
                setFailed(!(await installNetworkService()));
              }}
            >
              {busy && <LoaderCircle className="animate-spin" />}
              {busy ? "等待安装完成…" : action}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
