# Array Connect 桌面客户端

Tauri 2 + React/TypeScript，直接调用仓库中的 `arraysslvpn` Rust 库。前端使用官方 shadcn `radix-nova` 组件、Lucide 图标和 Zustand 状态管理。

## 功能

- 列表管理多个配置，首页可下拉切换；连接、认证、重连和清理期间始终只允许一个活动配置。活动配置断开后才能切换、编辑或删除。
- 网关、认证组、TLS 后端/CA/公钥固定、HTTP CONNECT/SOCKS5 代理、网卡、MTU、路由、DNS、解析地址、超时、DPD 等设置。
- 网关地址可输入 `vpn.example.com`、`192.0.2.1` 或 `vpn.example.com:8443`，自动补全 HTTPS；省略端口时使用 443。
- 密码、BASE32 密钥、代理密码保存在系统密钥库；配置、偏好和统计保存在 SQLite。前端只接收凭据是否存在，不提供读回明文的命令。
- 2FA 提供「手动填写密钥」和「自动注册」两种设置方式。手动密钥可留空，未保存密钥时每次认证输入验证码；填写 BASE32 密钥后自动生成验证码。未保存静态密码时，仍在 TLS 成功后请求输入。
- 自动注册由本机生成 80 bit 随机种子，使用配置的用户名和静态密码提交到 Array 网关。注册前明确提示并勾选确认：已有注册会被覆盖，旧验证器可能失效。注册只在点击按钮时进行，连接及重连不会重新注册。
- 使用 Array 的 SHA-1、6 位验证码，周期（1–300 秒）和钟差从网关获取；移除旧算法、位数、自定义周期及「自动认证」开关。最终认证密码为 `原静态密码 + 当前验证码`，不复用旧验证码。
- 显式点击「扫码添加到其它验证器」可显示标准 `otpauth://totp/` 二维码。密钥从系统密钥库读取，在 Rust 中生成 SVG，仅临时显示在对话框中；关闭后清空，日志和浏览器存储不记录二维码。目标 TOTP App 需支持网关提供的周期。
- 实时日志、搜索、等级筛选、暂停显示、复制；采集等级在偏好设置中立即生效。内存最多保留 2,000 条，日志不自动写入文件。
- 连接时长、上传/下载流量、每秒网速与最近 60 秒曲线；悬停图表可查看采样时间和上传/下载速度。每 5 秒保存一次统计，正常断开时保存最终值；重启会将未正常结束的记录标记为中断。
- 开机自启（启动应用，不自动连接 VPN）、浅色/深色/跟随系统外观。
- macOS 使用系统窗口圆角、红黄绿按钮和独立的单色菜单栏图标，图标由系统随菜单栏外观着色。
- 点击关闭窗口时询问「最小化到托盘」或「退出程序」，可勾选「不再询问」记住本次选择；在偏好设置中可恢复每次询问。托盘单击恢复窗口，右键菜单按实际状态显示未连接、取消连接或断开 VPN。
- 窗口、托盘、侧栏等所有退出入口在连接尚未结束时始终询问是否断开，不受已记住的关闭方式影响。实际退出等待 VPN 清理、配置及统计写入完成；确认后拒绝新连接和配置写入。旧版关闭偏好迁移为默认每次询问。

## 开发和构建

需要 Rust stable、Node.js 22.12+（或较新的 24/26）与 pnpm 12。Windows 使用 MSVC 工具链、WebView2、Perl 和 NASM；Linux 需要 WebKitGTK 4.1、GTK3、DBus 和 Secret Service；macOS 需要 Xcode 命令行工具。

```sh
cd desktop
pnpm install --frozen-lockfile
pnpm tauri dev
pnpm tauri build
```

默认将 OpenSSL 从源码构建并静态链接，GUI 仍默认选择 Rustls。旧版 Array 网关可在配置的「高级 → TLS 后端」中显式选择 OpenSSL，不需要目标机器另外安装 OpenSSL。

CLI 与桌面端的可执行文件都叫 `array-connect`（Windows 为 `array-connect.exe`），分别构建到仓库根目录的 `target` 和 `desktop/src-tauri/target`。同时构建两者时，请使用不同的 Cargo 输出目录。

Windows 的准备脚本从 [Wintun 官方网站](https://www.wintun.net/) 下载签名的 0.14.1 ZIP，按官方公布的 SHA-256 校验，选择当前架构的 DLL 并附带原始许可证。`tauri dev/build` 会自动执行准备步骤；开发版将 DLL 放到 EXE 同目录，安装包将它放入应用目录。脚本只下载和复制文件，创建 VPN 网卡发生在用户连接时。

修改 `assets/macos-tray.svg` 后，可在 `desktop` 目录运行 `pnpm tauri icon assets/macos-tray.svg --png 36 --output src-tauri/icons`，再将生成的 `36x36.png` 命名为 `macos-tray.png`。

仅开发浏览器界面：

```sh
pnpm dev
```

浏览器模式明确显示预览标记，不模拟成功连接、凭据存储或系统设置。连接等功能需要 Tauri 原生端。

## 权限和数据

Windows EXE 已嵌入 `requireAdministrator` 清单，启动时由系统请求 UAC 管理员授权。Windows 开发时请从管理员终端执行 `pnpm tauri dev`。同一 Windows 用户的普通和管理员进程共享系统凭据库。Linux 建立连接仍需 root，并使用当前用户可用、已解锁的 Secret Service 保存凭据。

macOS 13 及以上的 Developer ID 签名版支持让桌面客户端以普通用户身份建立连接。把 `Array Connect.app` 安装到「应用程序」后打开。首次启动会弹出管理员授权提示，点击「继续授权」会打开系统设置。在「登录项与扩展」中允许 Array Connect 后台运行，按系统提示完成管理员认证。回到应用即可连接，授权有效期间后续启动无需重复操作。 [Apple Service Management 文档](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)

后台服务通过 `SMAppService` 注册，GUI 和服务通过 XPC 核验对端的签名、Team ID 和标识。服务只接收网络参数，负责创建 utun、管理路由及临时 DNS，并在断开连接、GUI 退出或 XPC 连接失效时清理。TLS、密码、OTP 和密钥库留在普通用户进程中。可在系统设置中停用后台项目。

使用 ad-hoc 包或较早的 macOS 时，可从有管理员权限的账户运行 CLI。配置可参考仓库根目录的 `config.example.toml`。

```sh
sudo ./array-connect --config ./config.toml
```

CLI 在终端提示输入密码。网关要求 OTP 时，按网关要求在静态密码后追加当前验证码。

如需接入 macOS 系统 VPN 管理，可将数据面适配为 Network Extension 的 Packet Tunnel Provider，由系统应用 VPN 网络设置。直接分发需要按 Apple 的部署要求配置 Developer ID 签名和 Network Extension entitlement。[Apple Network Extension 部署说明](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

Windows 开机自启使用当前用户 SID 对应的交互式计划任务，以最高可用权限启动，兼容管理员清单，不保存 Windows 登录密码、不作为 SYSTEM 服务运行；已有普通登录启动项会迁移到此任务。macOS/Linux 继续使用 Tauri 官方 autostart 插件。所有平台均只启动应用，不自动连接 VPN。

从旧版升级后首次启动，Windows 会更新指向同一安装目录中旧 EXE 的已启用自启任务。macOS/Linux 若之前开启过自启，升级后可关闭再开启一次，刷新系统登记的启动路径。

数据位于 Tauri 按应用标识 `com.taurusxin.arrayconnect` 解析的 `app_data_dir` 中（以「偏好设置」显示的实际路径为准），数据库文件名为 `array-connect.sqlite3`。数据库不含密码、验证码、BASE32 密钥或代理密码。删除配置会删除对应的系统密钥库项，保留历史统计。取消「保存密码」、关闭 2FA 或关闭代理并保存，会移除相应已保存凭据。

明文凭据仅通过本地 Tauri IPC 从输入框发送给 Rust，提交或关闭输入框后清空表单，不放入 Zustand 持久化或 localStorage。二维码导出是用户显式触发的密钥共享操作，返回临时 SVG，不提供通用明文密钥读取命令。开启 Trace 后逐包日志仍不记录 IP 包内容。日志中的地址、路由、域名和用户名仍应按需要自行脱敏。

OTP 注册与 VPN 连接独立；注册前需断开 VPN，注册过程中不允许修改对应配置。候选密钥在 POST 前先保存到系统密钥库。如果响应丢失、取消时已提交，或服务器已注册但本地保存失败，将保留候选并标记待确认；重试复用同一个候选，不自动生成另一把密钥。待确认时阻止自动登录和二维码导出。移除本地密钥不会撤销网关注册。

旧配置首次读取时会移除旧 TOTP 字段；原 SHA-1/6 位且已启用自动认证的密钥继续使用。原本手动验证或非标准参数的配置改为手动验证，账号、网关、代理及历史统计保留。更换配置中的网关或用户名会清除该配置的旧 OTP 绑定，需要重新导入或注册。注册接口、密钥恢复机制和兼容性说明见 [OTP 协议说明](../docs/otp-enrollment.md)。

调试版可设置 `ARRAY_CONNECT_DATA_DIR` 指定隔离测试目录；发布版始终使用正常应用数据目录。该变量不改变凭据服务名，不应拿真实凭据进行自动化 UI 测试。

## 验证

macOS 上直接运行下面的 Cargo 检查前，先在 `desktop` 目录运行 `node scripts/prepare-macos-service.mjs`。Tauri 的 `dev` 和 `build` 会调用这一步。

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

Windows 还提供只解析内存任务定义、不注册任务的计划任务 XML 检查，以及不运行 EXE 的嵌入清单检查：

```powershell
cargo test --manifest-path src-tauri/Cargo.toml windows_accepts_the_task_definition_without_registering_it -- --ignored
./scripts/verify-windows-manifest.ps1 -Executable src-tauri/target/release/array-connect.exe
```

真实网关账号和网络恢复需在本机验收。DTLS、完整 IPv6 网络配置和原库已有的限制保持不变。强制终止进程不能保证完成正常网络清理。

## GitHub Release

推送 `v*` 版本 tag 时，与 CLI 一起构建 Windows、Linux、macOS（Apple Silicon / Intel）产物，全部成功后发布到同一个 Release。普通提交只运行检查及调试构建，不生成安装包。仅在明确要求发布新版时更新版本号和 tag；版本校验、产物及发布步骤见 [发布说明](../docs/releasing.md)。

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
