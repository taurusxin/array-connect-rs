# 打包与发布

仅在明确要求发布新版时更新版本号、创建并推送版本 tag。日常功能开发和修复不自动递增版本，也不创建 Release。

## 工作流

- `ci.yml`：分支推送、PR 和手动运行时，统一检查核心库、CLI、前端和三平台 Tauri 应用。构建调试应用验证清单，不生成安装包。
- `release.yml`：推送 `v*` tag 时触发。先验证 tag 与版本元数据，再分别打包 CLI 和桌面客户端；所有平台成功且产物齐全后，统一上传到同一个 GitHub Release，并生成 `SHA256SUMS`。

发布工作流不修改版本或创建 tag。`v1.2.3-rc.1` 等预发布 tag 会创建 GitHub Prerelease；普通版本 tag 创建正式 Release。单个平台失败时不会发布不完整的新 Release。失败后可在 Actions 中重跑，产物上传使用同一个 tag。

已有 tag 未触发或需要用修复后的工作流补跑时，可在 Release 的「Run workflow」中选择 `main` 并填写已有 tag，也可执行 `gh workflow run release.yml --ref main -f tag=v0.2.0`。工作流先检出该 tag 并校验版本，然后将所有构建和发布说明固定到该 tag 的提交；不会将 main 的应用源码作为旧版本发布，也不移动或重建已有 tag。

仓库通过 `.gitattributes` 将源码检出为 LF，并在桌面端明确 Prettier 的 LF 配置，避免 Windows 的 `core.autocrlf` 导致仅该平台格式检查失败。

构建任务只授予 `contents: read`，最终发布任务单独使用 `contents: write` 和内置 `GITHUB_TOKEN`，不需要额外的 GitHub PAT。仓库或组织策略需允许工作流使用该写权限。

## 下载产物

| 平台 | CLI | 桌面客户端 |
| --- | --- | --- |
| Windows x86_64 | ZIP，含 EXE、Wintun DLL 及许可证 | NSIS 安装程序，内含 Wintun |
| Linux x86_64 | tar.gz | DEB、AppImage，使用 Ubuntu 24.04 构建 |
| macOS Apple Silicon | tar.gz | DMG |
| macOS Intel | tar.gz | DMG |

资产名包含产品、版本、系统和架构，例如 `arraysslvpn-cli-1.2.3-windows-x86_64.zip`、`array-connect-1.2.3-macos-aarch64.dmg`。CLI 压缩包还附带 README、LGPL 许可证、上游归属及 TOML 示例。

两种产物中的可执行文件均为 `array-connect`，Windows 使用 `array-connect.exe`。Windows 的 NSIS 安装器仍使用 `Array Connect` 查找已有安装，升级时会使用已记录的旧 EXE 名称清理旧文件。应用标识 `com.taurusxin.arrayconnect` 用于关联现有应用数据。若选择先卸载旧版，保留用户数据时请勿勾选卸载器中的删除应用数据选项。

两种客户端均将 OpenSSL 从锁定的源码依赖静态链接，默认 TLS 后端仍为 Rustls。Windows CLI 的 Wintun 与桌面端使用同一下载脚本及 SHA-256 验证。当前 Windows 产物未做代码签名；macOS 使用 ad-hoc 签名，未配置 Apple Developer 签名及 notarization。

Windows 发布使用 PowerShell 执行编译，枚举 PATH 中的所有 Perl，逐个探测平台并选择单个 `MSWin32` 原生解释器，检查 OpenSSL 所需模块后将绝对路径写入 `OPENSSL_SRC_PERL` / `PERL`。找不到原生解释器时明确列出检查过的路径并停止。这样可避免将多个路径当成一个程序调用，或使用 MSYS Perl 导致 `Locale/Maketext/Simple.pm` 查找失败及 Windows 模块路径被错误解析。Linux/macOS 继续使用 Bash。

## 发布新版时

1. 完成修改、验收并将发布说明写入 `docs/releases/v目标版本.md`。工作流优先使用该文件作为 Release 正文；未提供时由 GitHub 自动生成。
2. 将以下文件中的项目版本统一为目标版本（不含 `v`），保留其他依赖版本：
   - 根目录 `Cargo.toml`、`Cargo.lock` 中的 `arraysslvpn`。
   - `desktop/package.json`、`desktop/src-tauri/Cargo.toml`、`desktop/src-tauri/tauri.conf.json`。
   - `desktop/src-tauri/Cargo.lock` 中的 `arraysslvpn` 与 `arraysslvpn-desktop`。
   - 前端 `desktop/src/stores/app.ts` 中用于浏览器预览的版本回退值。
3. 运行检查，并校验目标 tag。例如：

   ```sh
   python -B -m unittest discover -s .github/scripts -p 'test_*.py'
   python .github/scripts/release.py validate --tag v1.2.3
   ```

4. 提交发布元数据，并在该提交上创建对应 tag。先推送 main，确认默认分支已包含发布工作流，再单独推送版本 tag。版本校验通过后，GitHub Actions 自动打包发布；等待 Release 和两种客户端的全部资产实际出现后，才确认发布完成。

当前库与桌面端的开发版本可以不同；发布前必须统一。校验失败会直接停止发布，不会自动改版本来迁就 tag。完整三平台打包和上传需由 GitHub 托管 runner 验证，本地脚本测试不代表已在 GitHub 发布成功。
