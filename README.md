# SOCKS5 Tester (Android APK 自动构建模板)

你说“做成 APK 发给我”。

这里的运行环境缺少 Android SDK/NDK 与 Docker，没法直接把 Buildozer 跑起来生成 APK，所以我不能在对话里直接编译出 APK 文件给你。

我已经把代码整理成 **可自动出 APK** 的工程模板：你把整个目录上传到 GitHub 后，会自动编译并产出 APK（在 Actions 的 Artifacts 里下载）。

## GitHub Actions 一键出 APK（推荐）

1) 在 GitHub 新建一个仓库（私有/公开都行）。

2) 把本工程所有文件上传到仓库根目录（结构别改）：
- `app/`（代码 + buildozer.spec）
- `.github/workflows/build-android.yml`（自动构建）

3) 打开仓库的 **Actions** 标签页 → 运行 `Build Android APK`。
- 你 push 代码后会自动触发一次；也可以点右侧 `Run workflow` 手动触发。

4) 等构建完成后，在该次运行页面底部找到 **Artifacts**，下载 `apk`。

5) 把下载的 `*.apk` 传到手机安装（需要允许“安装未知来源应用”）。

> 这个模板使用 Buildozer 官方 Docker 环境进行构建，GitHub Actions 的示例来自 `ArtemSBulgakov/buildozer-action`。

## 电脑本地构建（可选）

在 Linux/WSL 上：
```bash
cd app
pip install buildozer
buildozer android debug
```
生成的 APK 在 `app/bin/` 下。

## 使用提醒

- **目标地址是“代理服务器视角”**：如果你在手机里填 `127.0.0.1`，等价于让 *代理服务器* 去连它自己的本机回环。
- 工具只做 SOCKS5 CONNECT + 发送/分块发送测试。

