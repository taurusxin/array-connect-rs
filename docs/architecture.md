# 代码目录与模块职责

项目保持单个 Cargo package，同时构建 `arraysslvpn` 库与同名 CLI。库入口统一导出供 GUI 使用的公共类型；终端输入、日志初始化和信号处理由 CLI 负责。

```text
src/
├── lib.rs                       # 库入口与公共 API 导出
├── config.rs                    # 类型化认证、TLS、网络和重连配置
├── error.rs                     # 公共错误类型
├── auth/
│   ├── mod.rs                   # 密码请求接口
│   ├── session.rs               # 登录、Cookie 会话、隧道升级与注销
│   └── cookie.rs                # 外部 Cookie 校验
├── client/
│   ├── mod.rs                   # VpnClient 与连接编排
│   ├── handle.rs                # 可克隆控制句柄
│   ├── session.rs               # 配置协商、数据转发、DPD、重连和清理
│   ├── state.rs                 # 状态、事件、统计和会话共享状态
│   └── timeout.rs               # 可取消的操作超时
├── protocol/
│   ├── mod.rs                   # Array 消息常量与协议类型导出
│   ├── config.rs                # IPv4、路由、DNS 和 DPD 配置解析
│   ├── framing.rs               # 配置 JSON 增量解码与结束符边界
│   └── packet.rs                # 原始 IP 和 Array 控制包增量解码
├── transport/
│   ├── mod.rs                   # TCP 建连与保留读取余量的 Wire
│   ├── http.rs                  # HTTP 响应头和消息体边界
│   ├── proxy.rs                 # HTTP CONNECT 与 SOCKS5
│   └── tls/
│       ├── mod.rs               # TLS 后端选择、证书公钥固定与元数据
│       ├── rustls.rs            # 默认 Rustls 后端
│       └── openssl.rs           # 可选 OpenSSL 兼容后端
├── network/
│   ├── mod.rs                   # PacketIo、NetworkManager 公共接口
│   ├── routes.rs                # 跨平台路由规划与排除规则
│   └── system/
│       ├── mod.rs               # TUN 生命周期与网络回滚记录
│       ├── windows.rs           # Windows 系统网络实现
│       ├── linux.rs             # Linux 系统网络实现
│       └── macos.rs             # macOS 系统网络实现
└── bin/arraysslvpn/
    ├── main.rs                  # CLI 入口、信号处理和运行模式
    ├── args.rs                  # 参数、TOML 合并及连接配置转换
    ├── logging.rs               # 文本/JSON 日志和输出目标
    └── password.rs              # 隐藏密码输入与显式 stdin 输入

tests/                           # 本地模拟网关和显式启用的系统网络检查
examples/                        # GUI 接入示例
docs/                            # 开发说明
.github/workflows/               # 三平台 CI
```

`client` 编排 `auth`、`protocol`、`transport` 和 `network`。`transport` 处理连接与字节流边界，`protocol` 处理 Array 配置和 IP 数据，`network` 通过可注入接口应用配置并读写数据包。公共配置与错误类型保留在库根目录，供这些模块共用。

目录调整保留 `arraysslvpn::VpnClient`、`arraysslvpn::NetworkSettings` 等根导出，以及 `arraysslvpn::protocol` 和 `arraysslvpn::network` 的既有公共路径。调用方通过公共 API 接入，不依赖内部文件位置。

`cli` feature 控制命令行依赖，`system-network` 控制系统网络实现，`openssl-tls`/`openssl-vendored` 控制可选 TLS 兼容后端。目录划分不引入新的 crate、运行时或全局日志初始化。
