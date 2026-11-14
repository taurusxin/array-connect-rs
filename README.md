# arraysslvpn

使用 Rust 实现的 Array Networks SSL VPN 客户端。单个 Cargo package 同时提供异步库和命令行程序，供后续 GUI 直接接入。

协议依据 OpenConnect 的 Array 模块移植，业务逻辑不调用 libopenconnect；默认 TLS 使用 Rustls + ring，不链接 OpenSSL。可选 OpenSSL 兼容后端需要显式编译和选择。ring 内含 C/汇编，Windows 使用独立的 Wintun 驱动。

## 当前能力

- 认证组、用户名密码、外部 ANsession Cookie；仅认证并导出 Cookie。
- TLS 1.2/1.3、系统根证书、额外 PEM CA、公钥固定、自定义解析地址。
- HTTP CONNECT / SOCKS5 代理及用户名密码认证。
- IPv4 TUN、包含/排除路由、DNS 与搜索域、断开回滚；Windows、Linux、macOS 后端。
- 原始 IP 流的增量解析、DPD、退避重连、密码模式自动重新认证。
- 配置 JSON 之间及配置到 IP 流的切换兼容最多 16 字节 NUL/空白结束符，支持分片到后续 TLS 读取；保留下一帧的完整 16 字节头。
- 类型化事件、状态订阅、流量统计、可取消连接及可注入的网络/数据包接口。
- 文本/JSON 日志、文件输出；密码、Cookie、代理认证信息不写入日志。

DTLS、完整 IPv6 网络配置、OTP/MFA、浏览器 SSO 和后台提权服务尚未实现。IPv6 数据包可以解码和转发，但本版本不分配 IPv6 地址或配置 IPv6 路由/DNS。

默认后端需要网关支持 Rustls 的 TLS 1.2/1.3 和密码套件。仅支持静态 RSA/CBC（例如 AES128-SHA）的网关可使用下述可选兼容后端。两个后端均不支持 TLS 1.0/1.1，不会自动更换后端或退回不加密 UDP。

## 仓库结构

源码按职责划分为 `src/auth`、`src/client`、`src/protocol`、`src/transport` 和 `src/network`；CLI 位于 `src/bin/arraysslvpn`。VPN 库与 CLI 保持单个 Cargo package，公共 API 由 `src/lib.rs` 统一导出。完整目录与职责见 [代码结构说明](docs/architecture.md)。

Tauri 2 桌面客户端位于 [desktop](desktop/README.md)，作为独立应用 package 通过路径依赖接入本库，提供 Nova 界面、多配置、系统密钥库、自动 2FA、实时日志与 SQLite 流量统计。

## 旧网关的可选 OpenSSL 后端

某些 Array 设备只接受 TLS 1.2 + AES128-SHA，并且会重置包含 TLS 1.3 声明的 ClientHello。Rustls 不支持静态 RSA 密钥交换或 CBC 套件，修改 CA 或使用 --insecure 不能启用这些套件。

~~~console
# 从源代码内嵌构建 OpenSSL，不需要在运行机器上安装 OpenSSL DLL
cargo build --release --locked --features openssl-vendored

# 或链接开发环境已有的 OpenSSL（需配置对应头文件和库）
cargo build --release --locked --features openssl-tls
~~~

源码构建需要 Perl、C 编译工具；Windows MSVC 还需要 NASM。首次编译 OpenSSL 可能耗时数分钟。

发布产物使用 openssl-vendored：从锁定的依赖源码构建 OpenSSL 并静态链接到程序，目标机器无需安装 OpenSSL 或随包携带 libssl/libcrypto 动态库。CI 的 release 构建也使用该 feature。普通 cargo build 仍使用不含 OpenSSL 的默认配置；openssl-tls 则使用构建环境中发现的库，具体静态/动态链接取决于构建环境，不作为标准发布方式。Windows 的 wintun.dll 仍需单独随应用提供。

兼容构建仍默认使用 Rustls。通过 --tls-backend openssl 或 TOML 的 tls-backend = "openssl" 显式选择；该兼容配置只发送 TLS 1.2 ClientHello，允许 OpenSSL DEFAULT 套件，并保持证书验证。可用 --openssl-ciphers AES128-SHA 限定套件。

~~~powershell
# 只做 TCP/TLS 探测，无需管理员、Wintun 或账号密码，不发送 HTTP
.\target\release\arraysslvpn.exe vpn.example.com --tls-backend openssl --tls-probe

# 网关证书暂未受信任时，只做无凭据探测并显示观测到的公钥指纹
.\target\release\arraysslvpn.exe vpn.example.com --tls-backend openssl --tls-probe --insecure

# 与管理员核对证书指纹后，再固定公钥连接
.\target\release\arraysslvpn.exe vpn.example.com --tls-backend openssl --servercert "pin-sha256:已确认的BASE64指纹" -u your-user -vv
~~~

--tls-probe 向 stdout 输出 JSON：后端、协议、密码套件和 SPKI 指纹。未验证连接中观测到的指纹不能单独证明服务器身份，应与可信来源核对后使用。兼容后端同样支持系统根证书、自定义 CA、公钥固定、代理、认证和隧道转发。

## 构建与连接

安装 Rust stable 和对应平台的编译工具：

~~~console
cargo build --release --locked
cargo run -- --help
~~~

Windows 生成 `target\release\arraysslvpn.exe`；Linux/macOS 生成 `target/release/arraysslvpn`。

### Windows

从 [Wintun 官方网站](https://www.wintun.net/) 获取匹配架构的 `wintun.dll`，放在实际执行的 EXE 旁边。程序仅从 EXE 所在目录加载该 DLL。使用管理员终端运行。

~~~powershell
.\target\release\arraysslvpn.exe https://vpn.example.com -u your-user --authgroup local -v
~~~

交互式密码提示出现在 TCP/TLS 握手和配置的证书校验策略通过之后，随后在同一条 TLS 连接上提交登录。握手或证书校验失败不会要求输入密码。输入保持隐藏，支持粘贴、退格和 Ctrl+C/Esc 取消，等待输入不计入连接超时。配置文件中不保存密码。Windows DNS API 要求 Windows 10 2004 / Server 2022 或更新系统。

### Linux

需要 root、可用的 `/dev/net/tun` 和 iproute2（`ip` 命令）。DNS 自动选择 systemd-resolved 的 `resolvectl`，或支持 `-a/-d/-m/-x` 的 resolvconf。没有这些解析器时，可显式使用 `--no-dns` 自行管理 DNS。

~~~sh
sudo ./target/release/arraysslvpn https://vpn.example.com -u your-user -v
~~~

### macOS

需要管理员权限，使用系统 utun、路由套接字及 scutil/SystemConfiguration 动态 DNS。默认让系统分配 utun 名称，显式指定名称时使用未占用的 `utunN`。

~~~sh
sudo ./target/release/arraysslvpn https://vpn.example.com -u your-user -v
~~~

macOS 后端面向普通桌面进程；沙箱应用/商店分发的 Network Extension 接入不在此版本范围内。

## 常用参数

完整列表见 `--help`。下面的主机名和凭据均为示例。

~~~sh
# 仅登录，stdout 输出 Cookie；不创建网卡，不需要管理员权限
arraysslvpn vpn.example.com -u your-user --authenticate

# 仅认证时将 Cookie 保存到受保护的文件，由使用者管理文件权限及生命周期
arraysslvpn vpn.example.com -u your-user --authenticate > session.cookie
arraysslvpn vpn.example.com --cookie-file session.cookie

# 使用私有 CA，或固定公钥（两种信任方式择一）
arraysslvpn vpn.example.com -u your-user --cafile company-ca.pem
arraysslvpn vpn.example.com -u your-user --servercert 'pin-sha256:BASE64_SHA256_SPKI'

# SOCKS5 或 HTTP CONNECT 代理；代理 URL 的凭据需要百分号编码
arraysslvpn vpn.example.com -u your-user --proxy socks5://127.0.0.1:1080
arraysslvpn vpn.example.com -u your-user --proxy http://127.0.0.1:8080

# 固定连接 IP，TLS SNI 与 HTTP Host 仍使用 vpn.example.com
arraysslvpn vpn.example.com -u your-user --resolve 203.0.113.10 --port 443

# 自定义路由和网络配置
arraysslvpn vpn.example.com -u your-user --route-mode server --route 10.20.0.0/16 --exclude-route 192.168.0.0/16
arraysslvpn vpn.example.com -u your-user --route-mode none --no-dns --mtu 1300

# 不重连，或覆盖 DPD 间隔
arraysslvpn vpn.example.com -u your-user --reconnect-timeout 0 --dpd 30

# 详细日志：-v 为 debug，-vv 为 trace；逐包只记录方向、长度和类型
arraysslvpn vpn.example.com -u your-user -vv --log-format json --log-file vpn.log
~~~

自动化调用支持 `--passwd-on-stdin` / `--cookie-on-stdin`，读取一行；这些显式提供凭据的方式保持预先读取。用户名密码和 Cookie 认证不能混用。认证失败停止重试。Cookie 过期时返回 Authentication；密码模式重连使用本次会话内存中的密码重新登录，避免重复弹出输入框。

`--servercert` 接受 `pin-sha256:` 加 base64 编码的 SHA-256 SPKI 摘要。提供 pin 时，它代替 CA/域名验证，仍校验 TLS 握手签名；多个 pin 为任意一个匹配。`--insecure` 是显式跳过 CA/域名校验的独立选项，不能与 pin 一起使用。

复制 [config.example.toml](config.example.toml) 后使用：

~~~sh
arraysslvpn --config config.local.toml
arraysslvpn --config config.local.toml --mtu 1300 --no-dns
~~~

优先级为 CLI > TOML > 默认值。列表参数在 CLI 提供后替代配置文件中的对应列表。布尔参数允许 `--insecure=false`、`--no-dns=false` 覆盖文件设置。配置文件拒绝 password/cookie 等明文凭据字段；可以指定 Cookie 文件。代理 URL 若含凭据，应由使用者保护该配置文件。

日志默认写 stderr，`--log-file` 改为追加文件；仅 `--authenticate` 会按明确请求向 stdout 输出秘密 Cookie。日志有网络地址、路由和域名，分享前可进一步脱敏。

## 路由、DNS 与清理

- 默认 `route-mode=server`：服务器有包含路由时分流，否则使用 IPv4 全隧道；CLI 的 `--route` 追加网络。
- `route-mode=full` 使用 IPv4 全隧道。服务器和 CLI 的排除网络始终优先。全隧道使用两个 /1，不替换物理默认路由。
- `route-mode=none` 不添加受管路由。需要连 DNS 也保持原状时同时使用 `--no-dns`。
- TUN 使用点对点 /32 地址，服务器公布的原始掩码保留在 NetworkSettings；所有受管网络经显式路由转发，避免自动直连路由绕过排除规则。
- 修改网络前记录实际 TCP 对端（直连网关或代理）的原出口，保留旁路，并从隧道路由中排除该地址。
- 自动管理 DNS 时补充 VPN DNS 的主机路由。DNS 与排除网络冲突则报错；不会静默向物理网络发送该 DNS 流量。Linux/macOS 的 VPN DNS 配置用于所有域名查询，不提供按域名分流模式。
- 不复用已存在的同名接口，不覆盖冲突路由；新建的临时接口、路由及 DNS 变更由本会话持有并清理。
- Ctrl+C、Unix SIGTERM、初始化失败、正常断开或重连最终失败时等待回滚。重连先恢复原网络，再重新应用新配置。
- 不是 kill switch：重连期间恢复物理网络；IPv6 系统流量不受 IPv4 隧道接管。强制终止进程/断电时无法保证用户态清理完成。

默认连接/每阶段读写超时 30 秒，重连窗口 300 秒，退避 1–30 秒加随机抖动；DPD 使用服务器值或 30 秒，连续三个间隔没有接收数据则重连。网络配置的 OS 操作等待完成后再处理取消，以保证回滚记录完整。

## 接入 Rust / GUI

仅使用库和系统网络：

~~~toml
[dependencies]
arraysslvpn = { path = "../arraysslvpn-rs", default-features = false, features = ["system-network"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
~~~

~~~rust,no_run
use arraysslvpn::{AuthConfig, ClientConfig, VpnClient};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
// 将 GUI 登录框提供的密码转换为 SecretString。
let auth = AuthConfig::Password {
    username: "your-user".into(),
    password: "password-from-login-dialog".into(),
    authgroup: "local".into(),
};
let client = VpnClient::new(ClientConfig::new("https://vpn.example.com", auth)?)?;
let controller = client.handle();
let events = controller.subscribe(); // 在 connect 前订阅，可看到认证和网络配置状态

let worker = tokio::spawn(async move {
    client.connect().await?.run().await
});

// GUI 保存 controller，异步处理 events；点击断开时：
controller.disconnect();
worker.await??; // 等待网络恢复结束后再退出应用
# Ok(())
# }
~~~

完整事件消费示例见 [examples/gui_integration.rs](examples/gui_integration.rs)。调用方安装自己的 tracing subscriber，即可把日志接入 GUI。

- `VpnClient::authenticate()` 只返回受保护的会话 Cookie。
- `AuthConfig::DeferredPassword` 接受 `PasswordProvider`：在 TLS 成功后以 `PasswordChallenge` 请求密码，其中包含用户名、认证组、TLS 信息和取消令牌；GUI 可在此时显示登录框。等待输入时状态为 `AwaitingPassword`。provider 必须响应取消并在返回前清理界面；普通 `AuthConfig::Password` 仍支持预先提供凭据。
- `connect()` 完成认证、协商、网络配置，返回 VpnSession；`run()` 驱动转发和重连。
- 未运行的 VpnSession 可调用 `disconnect().await` 清理；运行中的会话由控制句柄取消，再等待 `run()` 返回。
- SessionHandle 提供 `subscribe()`、`watch_state()`、`stats()`；事件广播不会因慢接收者阻塞隧道，Lagged 后可读状态/统计重新同步。
- 取消连接/运行请使用控制句柄，并等待对应 future 返回；不要直接 abort 连接任务。Drop 只有系统网络的同步最佳努力清理，不执行异步远程注销。
- 禁用全部默认 features 时仍可使用协议和认证，以及 `connect_with(Box<dyn NetworkManager>)`，由调用方提供网络管理及 PacketIo。PacketIo.recv 必须符合文档中的取消安全约定。
- 库不创建 Tokio runtime，不初始化全局日志，不安装信号处理器，不读终端，也不持久化凭据。

## 验证

~~~sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo test --locked --no-default-features
cargo check --locked --no-default-features --features system-network --all-targets
cargo test --locked --all-targets --features openssl-vendored
~~~

模拟测试使用本地 TLS Array 服务及内存数据包接口，不创建网卡或修改主机网络。覆盖登录、Cookie、分片/粘包、JSON 尾部 NUL/空白与零值帧头、非法尾部、证书、HTTP/SOCKS5 代理、DPD、断线重认证、配置变化、取消、失败回滚及日志脱敏。OpenSSL feature 另测试仅允许 TLS 1.2/AES128-SHA 的服务器、证书验证、公钥固定和无凭据探测。

真实系统网络检查默认忽略，显式设置环境变量后以管理员/root 运行：

~~~powershell
# Windows；wintun.dll 需放在 target/debug/deps 中，即测试 EXE 的目录
$env:ARRAYSSLVPN_PRIVILEGED_TEST = "1"
cargo test --test system_network -- --ignored
~~~

~~~sh
# Linux/macOS，需在能找到 Rust 工具链的 root 环境中执行
sudo -E env ARRAYSSLVPN_PRIVILEGED_TEST=1 cargo test --test system_network -- --ignored
~~~

该检查创建临时 TUN 和 TEST-NET 路由，验证重复清理，不修改 DNS。DNS 需要配合真实网关手动验收。

三平台原生 CI 配置位于 [.github/workflows/ci.yml](.github/workflows/ci.yml)。当前验证包括 Windows 编译、模拟测试及旧版 Array 网关的 TLS 1.2/AES128-SHA 握手；使用者已在本机验证真实网关连接通过。Linux/macOS 原生 CI、真实 TUN/DNS 的独立集成检查及长期稳定性仍待验证。

真实网关联调建议先用 `--authenticate -vv` 确认 TLS/登录，再连接并检查内网 IP、内网域名、持续传输、断网重连及退出后的路由/DNS 恢复。报错时可分享脱敏日志，无需提供密码/Cookie。

## 协议依据与许可证

[OpenConnect Array 源码](https://gitlab.com/openconnect/openconnect/-/blob/master/array.c)、
[Array 协议说明](https://www.infradead.org/openconnect/array.html)。

LGPL-2.1-only，见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。Wintun 未随本仓库分发。
