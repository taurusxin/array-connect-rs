import {
  Check,
  Database,
  KeyRound,
  Laptop,
  Moon,
  Palette,
  Power,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Terminal,
  PanelBottomClose,
} from "lucide-react";
import { Choice, ToggleRow } from "@/components/fields";
import { useApp } from "@/stores/app";
import {
  networkServiceLabels,
  type Preferences as Settings,
} from "@/lib/types";

export function Preferences() {
  const app = useApp();
  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">MAKE IT YOURS</div>
          <h1>偏好设置</h1>
          <p>为你的工作习惯，做一点调整。</p>
        </div>
        <span className="saved-indicator">
          <Check size={13} />
          自动保存
        </span>
      </header>
      <section className="panel settings-panel">
        <div className="settings-section-heading">
          <span className="setting-icon">
            <Palette size={19} />
          </span>
          <div>
            <h2>外观</h2>
            <p>选择适合你的显示方式。</p>
          </div>
        </div>
        <div className="theme-options">
          {(
            [
              ["light", "浅色", Sun],
              ["dark", "深色", Moon],
              ["system", "跟随系统", Laptop],
            ] as const
          ).map(([key, label, Icon]) => (
            <button
              key={key}
              className={`theme-option ${app.preferences.theme === key ? "selected" : ""}`}
              onClick={() =>
                void app.setPreferences({ ...app.preferences, theme: key })
              }
            >
              <div className={`theme-preview ${key}`}>
                <div className="preview-sidebar" />
                <div className="preview-content">
                  <i />
                  <i />
                  <span>
                    <b />
                    <b />
                    <b />
                  </span>
                </div>
              </div>
              <span>
                <Icon size={14} />
                {label}
                {app.preferences.theme === key && (
                  <Check size={14} className="theme-check" />
                )}
              </span>
            </button>
          ))}
        </div>
      </section>
      <section className="panel settings-panel">
        <div className="settings-section-heading">
          <span className="setting-icon">
            <SlidersHorizontal size={19} />
          </span>
          <div>
            <h2>通用</h2>
            <p>启动行为与诊断选项。</p>
          </div>
        </div>
        <ToggleRow
          icon={<Power size={18} />}
          label="开机自启"
          hint={
            app.autostartError ??
            (app.platform === "windows"
              ? "使用当前用户的交互式计划任务，以管理员权限启动，不会自动连接 VPN。"
              : "登录系统后自动启动 Array Connect，不会自动连接 VPN。")
          }
          checked={app.autostart}
          onChange={(value) => void app.setAutostart(value)}
          disabled={app.busy || app.autostartError !== null}
        />
        <div className="setting-select-row">
          <span className="setting-icon">
            <PanelBottomClose size={18} />
          </span>
          <div>
            <h3>关闭窗口时</h3>
            <p>
              可修改已记住的选择。退出应用时若连接尚未结束，始终确认是否断开。
            </p>
          </div>
          <Choice
            label="关闭方式"
            value={app.preferences.closeBehavior}
            onChange={(value) =>
              void app.setPreferences({
                ...app.preferences,
                closeBehavior: value as Settings["closeBehavior"],
              })
            }
            options={[
              ["ask", "每次询问（默认）"],
              ...(app.trayAvailable
                ? [["tray", "最小化到托盘"] as [string, string]]
                : []),
              ["exit", "退出程序"],
            ]}
          />
        </div>
        <div className="setting-select-row">
          <span className="setting-icon">
            <Terminal size={18} />
          </span>
          <div>
            <h3>日志采集等级</h3>
            <p>调整后立即生效。Trace 会记录逐包方向、长度及类型。</p>
          </div>
          <Choice
            label="采集等级"
            value={app.preferences.logLevel}
            onChange={(value) =>
              void app.setPreferences({
                ...app.preferences,
                logLevel: value as Settings["logLevel"],
              })
            }
            options={[
              ["error", "Error"],
              ["warn", "Warn"],
              ["info", "Info（默认）"],
              ["debug", "Debug"],
              ["trace", "Trace"],
            ]}
          />
        </div>
      </section>
      <section className="panel settings-panel">
        <div className="settings-section-heading">
          <span className="setting-icon">
            <Database size={19} />
          </span>
          <div>
            <h2>数据与凭据</h2>
            <p>本地保存，由你掌控。</p>
          </div>
        </div>
        <div className="settings-info-row">
          <KeyRound size={17} />
          <div>
            <h3>系统密钥库</h3>
            <p>
              登录密码、BASE32
              密钥和代理密码通过操作系统的凭据服务保存，界面不会读回明文。
            </p>
          </div>
          <span className="saved-indicator">
            <ShieldCheck size={14} />
            本机保护
          </span>
        </div>
        <div className="settings-info-row">
          <Database size={17} />
          <div>
            <h3>SQLite 数据库</h3>
            <p>
              保存连接配置、会话时长和累计流量。每 5
              秒保存统计，断开时写入最终值。
            </p>
            <code>
              {app.storagePath
                ? `${app.storagePath}/array-connect.sqlite3`
                : "桌面端启动后显示数据目录"}
            </code>
          </div>
        </div>
        <div className="settings-info-row">
          <ShieldCheck size={17} />
          <div>
            <h3>运行权限</h3>
            <p>
              {app.administrator
                ? "当前进程已有管理员/root 权限。"
                : app.networkService
                  ? networkServiceLabels[app.networkService]
                  : "编辑配置无需提权。建立 VPN 时请以管理员/root 身份运行。"}
              {!app.wintunAvailable &&
                " Windows 还需要在程序旁放置 wintun.dll。"}
            </p>
          </div>
        </div>
      </section>
      <footer className="preferences-about">
        <span className="about-mark">
          <ShieldCheck size={17} />
        </span>
        <span>
          <strong>Array Connect</strong>
          <small>基于 arraysslvpn · Tauri 2 · v{app.version}</small>
        </span>
        <span className="license-label">LGPL-2.1-only</span>
      </footer>
    </>
  );
}
