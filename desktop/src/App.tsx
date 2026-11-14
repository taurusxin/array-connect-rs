import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  Activity,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleHelp,
  Globe2,
  KeyRound,
  LayoutDashboard,
  LoaderCircle,
  LogOut,
  Minus,
  Settings2,
  ShieldCheck,
  ShieldAlert,
  Square,
  Terminal,
  Trash2,
  X,
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
import { TooltipProvider } from "@/components/ui/tooltip";
import { ProfileDialog } from "@/components/profile-dialog";
import { CredentialsDialog } from "@/components/credentials-dialog";
import { ExitDialog } from "@/components/exit-dialog";
import { Overview } from "@/pages/overview";
import { Profiles } from "@/pages/profiles";
import { Logs } from "@/pages/logs";
import { Preferences } from "@/pages/preferences";
import { native } from "@/lib/api";
import { stateLabels, type Profile } from "@/lib/types";
import { useApp } from "@/stores/app";

const navigation = [
  { page: "overview", label: "连接概览", icon: LayoutDashboard },
  { page: "profiles", label: "连接配置", icon: Globe2 },
  { page: "logs", label: "实时日志", icon: Terminal },
  { page: "preferences", label: "偏好设置", icon: Settings2 },
] as const;

export function App() {
  const app = useApp();
  const [editor, setEditor] = useState<{ profile: Profile | null } | null>(
    null,
  );
  const [deleting, setDeleting] = useState<Profile | null>(null);
  useEffect(() => {
    void app.initialize();
  }, []);
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () =>
      document.documentElement.classList.toggle(
        "dark",
        app.preferences.theme === "dark" ||
          (app.preferences.theme === "system" && media.matches),
      );
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [app.preferences.theme]);
  useEffect(() => {
    if (!app.notice) return;
    const timer = setTimeout(app.dismiss, 3000);
    return () => clearTimeout(timer);
  }, [app.notice]);
  return (
    <TooltipProvider>
      <div className="app-frame">
        <div className="titlebar" data-tauri-drag-region>
          <span data-tauri-drag-region>Array Connect</span>
          <div className="window-controls">
            {native && (
              <>
                <button
                  aria-label="最小化窗口"
                  onClick={() => void getCurrentWindow().minimize()}
                >
                  <Minus size={14} />
                </button>
                <button
                  aria-label="最大化窗口"
                  onClick={() => void getCurrentWindow().toggleMaximize()}
                >
                  <Square size={11} />
                </button>
                <button
                  className="window-close"
                  aria-label="关闭窗口"
                  onClick={() => void getCurrentWindow().close()}
                >
                  <X size={15} />
                </button>
              </>
            )}
          </div>
        </div>
        <div className="app-layout">
          <aside className="sidebar">
            <div className="brand">
              <div className="brand-icon">
                <ShieldCheck size={22} strokeWidth={1.8} />
              </div>
              <div>
                <strong>Array Connect</strong>
                <span>让连接，回归简单</span>
              </div>
            </div>
            <nav className="main-nav" aria-label="主导航">
              {navigation.map(({ page, label, icon: Icon }) => (
                <button
                  className={
                    app.page === page ? "nav-item selected" : "nav-item"
                  }
                  key={page}
                  onClick={() => app.setPage(page)}
                >
                  <Icon size={17} strokeWidth={1.8} />
                  <span>{label}</span>
                  {page === "profiles" && <small>{app.profiles.length}</small>}
                  {page === "logs" &&
                    app.logs.some((l) => l.level === "error") && (
                      <span className="nav-alert" />
                    )}
                </button>
              ))}
            </nav>
            <div className="sidebar-bottom">
              <div className="local-security">
                <span>
                  <KeyRound size={15} />
                </span>
                <div>
                  <strong>凭据留在本机</strong>
                  <small>由系统密钥库提供保护</small>
                </div>
              </div>
              <div className="sidebar-version">
                <span>v{app.version}</span>
                <button
                  title="退出客户端"
                  aria-label="退出客户端"
                  onClick={() => void app.requestExit()}
                >
                  <LogOut size={14} />
                </button>
                <button
                  onClick={() => app.setPage("preferences")}
                  title="关于与设置"
                >
                  <CircleHelp size={14} />
                </button>
              </div>
            </div>
          </aside>
          <div className="workspace">
            <div className="workspace-topbar">
              <div className="breadcrumb">
                <span>工作空间</span>
                <ChevronRight size={12} />
                <strong>
                  {navigation.find((n) => n.page === app.page)?.label}
                </strong>
              </div>
              <span className="global-status">
                <span
                  className={
                    app.session.state === "Connected"
                      ? "status-dot connected"
                      : "status-dot"
                  }
                />
                {stateLabels[app.session.state] ?? app.session.state}
              </span>
            </div>
            <main
              className={`main-content ${app.page === "logs" ? "logs-page" : ""}`}
            >
              {!app.initialized ? (
                <div className="loading-page">
                  <LoaderCircle className="animate-spin" />
                  <p>正在载入工作空间…</p>
                </div>
              ) : (
                <>
                  {native && !app.administrator && app.profiles.length > 0 && (
                    <div className="permission-note">
                      <ShieldAlert size={15} />
                      <span>
                        连接 VPN 需要管理员/root
                        权限。请退出后以管理员身份运行。
                      </span>
                    </div>
                  )}
                  {!native && (
                    <div className="preview-note">
                      <Activity size={14} />
                      界面预览 · 连接、凭据和系统设置仅在桌面客户端中可用
                    </div>
                  )}
                  {app.page === "overview" && (
                    <Overview edit={(profile) => setEditor({ profile })} />
                  )}
                  {app.page === "profiles" && (
                    <Profiles
                      edit={(profile) => setEditor({ profile })}
                      remove={setDeleting}
                    />
                  )}
                  {app.page === "logs" && <Logs />}
                  {app.page === "preferences" && <Preferences />}
                </>
              )}
            </main>
            <footer className="workspace-footer">
              <span>
                <ShieldCheck size={12} />
                Array Networks SSL VPN
              </span>
              <span>
                TLS 加密连接
                <ArrowUpRight size={11} />
              </span>
            </footer>
          </div>
        </div>
        {(app.error || app.notice) && (
          <div
            className={`toast ${app.error ? "error" : ""}`}
            role={app.error ? "alert" : "status"}
          >
            {app.error ? <ShieldAlert size={18} /> : <Check size={18} />}
            <span>{app.error ?? app.notice}</span>
            <button aria-label="关闭通知" onClick={app.dismiss}>
              <X size={14} />
            </button>
          </div>
        )}
        {editor && (
          <ProfileDialog
            profile={editor.profile}
            onClose={() => setEditor(null)}
          />
        )}
        {app.credentialRequest && app.exitState === "idle" && (
          <CredentialsDialog
            key={app.credentialRequest.id}
            request={app.credentialRequest}
          />
        )}
        {deleting && (
          <Dialog
            open
            onOpenChange={(open) => {
              if (!open) setDeleting(null);
            }}
          >
            <DialogContent>
              <DialogHeader>
                <DialogTitle>删除「{deleting.name}」？</DialogTitle>
                <DialogDescription>
                  同时移除系统密钥库中此配置的密码、2FA
                  密钥和代理密码。已有统计记录会保留。
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button
                  variant="outline"
                  onClick={() => setDeleting(null)}
                  disabled={app.busy}
                >
                  取消
                </Button>
                <Button
                  variant="destructive"
                  disabled={app.busy}
                  onClick={async () => {
                    if (await app.deleteProfile(deleting.id)) setDeleting(null);
                  }}
                >
                  <Trash2 />
                  删除配置
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
        <ExitDialog />
      </div>
    </TooltipProvider>
  );
}
