# Array Connect 桌面客户端

Tauri 2 + React/TypeScript，直接调用仓库中的 `arraysslvpn` Rust 库。前端使用官方 shadcn `radix-nova` 组件、Lucide 图标和 Zustand 状态管理。

## 功能

- 多配置管理；连接、认证、重连和清理期间始终只允许一个活动配置。活动配置断开后才能编辑或删除。
- 网关、认证组、TLS 后端/CA/公钥固定、HTTP CONNECT/SOCKS5 代理、网卡、MTU、路由、DNS、解析地址、超时、DPD 等设置。
- 密码、BASE32 密钥、代理密码保存在系统密钥库；配置、偏好和统计保存在 SQLite。前端只接收凭据是否存在，不提供读回明文的命令。
- 2FA 开关及自动认证：默认 SHA-1、6 位、30 秒，支持 SHA-256/SHA-512、8 位及自定义周期。最终密码为 `原密码 + 当前验证码`，中间不加分隔符。
- 关闭自动认证时，每次认证请求输入验证码。未保存密码时，在 TLS 成功后显示密码输入框。重连需要重新认证时生成新码或请求新的手动验证码，不复用过期验证码。
- 实时日志、搜索、等级筛选、暂停显示、复制；采集等级在偏好设置中立即生效。内存最多保留 2,000 条，日志不自动写入文件。
- 连接时长、上传/下载流量、每秒网速与最近 60 秒曲线。每 5 秒保存一次统计，正常断开时保存最终值；重启会将未正常结束的记录标记为中断。
- 开机自启（启动应用，不自动连接 VPN）、浅色/深色/跟随系统外观。
- 关闭窗口时取消连接并等待库清理网络，不直接中止连接任务。

## 开发和构建

需要 Rust stable、Node.js 22.12+（或较新的 24/26）与 pnpm 12。Windows 使用 MSVC 工具链、WebView2、Perl 和 NASM；Linux 需要 WebKitGTK 4.1、GTK3、DBus 和 Secret Service；macOS 需要 Xcode 命令行工具。

```sh
cd desktop
pnpm install --frozen-lockfile
pnpm tauri dev
pnpm tauri build
```

默认将 OpenSSL 从源码构建并静态链接，GUI 仍默认选择 Rustls。旧版 Array 网关可在配置的「高级 → TLS 后端」中显式选择 OpenSSL，不需要目标机器另外安装 OpenSSL。

Windows 的准备脚本从 [Wintun 官方网站](https://www.wintun.net/) 下载签名的 0.14.1 ZIP，按官方公布的 SHA-256 校验，选择当前架构的 DLL 并附带原始许可证。`tauri dev/build` 会自动执行准备步骤；开发版将 DLL 放到 EXE 同目录，安装包将它放入应用目录。脚本只下载和复制文件，创建 VPN 网卡发生在用户连接时。

仅开发浏览器界面：

```sh
pnpm dev
```

浏览器模式明确显示预览标记，不模拟成功连接、凭据存储或系统设置。连接等功能需要 Tauri 原生端。

## 权限和数据

编辑配置不需要管理员权限。当前版本使用现有库在前台管理 TUN、路由与 DNS，**实际连接需要以管理员/root 身份运行整个应用**；独立提权服务尚未实现。Windows 同一用户的普通/管理员进程共享该用户的系统凭据库。Linux 需要运行用户可用、已解锁的 Secret Service；密钥库不可用时返回明确错误，不回退到明文保存。

开机自启由 Tauri 官方 autostart 插件管理，状态直接读取操作系统。Windows 开机启动的普通进程仍需在连接前以管理员身份重新运行。

数据位于 Tauri 按应用标识 `com.taurusxin.arrayconnect` 解析的 `app_data_dir` 中（以「偏好设置」显示的实际路径为准），数据库文件名为 `array-connect.sqlite3`。数据库不含密码、验证码、BASE32 密钥或代理密码。删除配置会删除对应的系统密钥库项，保留历史统计。取消「保存密码」、关闭 2FA 或关闭代理并保存，会移除相应已保存凭据。

明文凭据仅通过本地 Tauri IPC 从输入框发送给 Rust，提交或关闭输入框后清空表单，不放入 Zustand 持久化或 localStorage。开启 Trace 后逐包日志仍不记录 IP 包内容。日志中的地址、路由、域名和用户名仍应按需要自行脱敏。

调试版可设置 `ARRAY_CONNECT_DATA_DIR` 指定隔离测试目录；发布版始终使用正常应用数据目录。该变量不改变凭据服务名，不应拿真实凭据进行自动化 UI 测试。

## 验证

```sh
pnpm build
pnpm test
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --lib
```

系统密钥库往返检查使用随机、独立的测试项，结束时删除，不读取已有用户凭据：

```sh
cargo test --manifest-path src-tauri/Cargo.toml system_keyring_roundtrip -- --ignored
```

真实网关账号和网络恢复需在本机验收。DTLS、完整 IPv6 网络配置和原库已有的限制保持不变。强制终止进程不能保证完成正常网络清理。

## 目录

```text
desktop/
├── src/components/ui/          # 官方 shadcn Nova 组件，图标固定为 Lucide
├── src/components/             # 配置/认证对话框、表单和网速曲线
├── src/pages/                  # 概览、配置、日志、偏好设置
├── src/stores/                 # Zustand 状态与事件订阅
├── src/lib/                    # IPC 类型和格式化
├── src-tauri/src/              # 连接控制、SQLite、系统密钥库、TOTP、日志
├── src-tauri/capabilities/      # 窗口与本地 IPC 权限
├── scripts/                    # 校验并准备 Wintun
└── fixtures/                   # 无敏感数据的协议/存储测试配置
```
