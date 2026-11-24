# 单管理员 Master 部署

新部署使用 Compose。系统生成首次登录凭据、状态任务签发密钥和 Core 管理签发密钥。远程 Agent 接入需要一个可从节点访问的 HTTPS 地址。

## 构建安装包和镜像

在安装了[项目指定工具链](./development-baseline.md)的 Linux 主机上构建。输出包含支持 amd64 和 arm64 的 Master 安装程序、SHA-256 文件，以及镜像构建上下文。

```sh
bash scripts/build-master-release.sh /tmp/mcui-master-release
docker buildx build --load -f deploy/master/Dockerfile \
  -t mcui-master:local /tmp/mcui-master-release/image
```

源码构建的本地镜像可以验证面板和启动流程。包含 GitHub Agent 安装元数据的镜像由[部署制品发布流程](./phase-3-release.md#发布-compose-和通用-agent)构建。

## systemd 安装

在运行 systemd 的 Linux amd64 或 arm64 主机上，使用带有效系统 CA 的环境。将已核对的 `SHA256SUMS` 和安装程序放在同一目录。

```sh
sha256sum --check --ignore-missing SHA256SUMS && sudo bash ./install-mcui-master.sh
```

安装程序启用 `mcui-master.service`。默认访问地址为 `http://127.0.0.1:8080`，配置在 `/etc/mcui-master/panel.env`，数据库和缓存位于 `/var/lib/mcui-master`。首次安装在终端输出初始用户名和密码。安装前保留管理终端的访问控制，首次登录设置至少 12 字符的新密码并绑定 TOTP MFA。服务重启使用已有管理员和数据库。

升级前备份数据库和配置，再校验并运行新版本安装程序。程序使用版本化目录并在新服务启动失败时尝试恢复上一版本。跨数据库版本的回退按备份恢复流程执行。已有手工部署迁移时先备份，再在隔离副本验证。单管理员入口要求库中唯一启用的账号是全局安全管理员。

未完成首次设置且初始密码遗失时，使用本地恢复入口轮换。执行前停止服务。

```sh
sudo systemctl stop mcui-master
sudo -u mcui-master /opt/mcui-master/current/mcui-panel \
  -db /var/lib/mcui-master/mcui.db -recover-initial-admin
sudo systemctl start mcui-master
```

## Compose 安装

从项目 GitHub Release 下载 `compose.yaml`。在文件所在目录启动主控并查看首次凭据。

```sh
docker compose up -d
docker compose logs master
```

默认镜像是 `ghcr.io/acnoway/mcui-master:latest`。本机打开 `http://127.0.0.1:8080`，首次登录时设置自己的密码并绑定 TOTP MFA。可通过 `MCUI_MASTER_PORT` 调整本机端口，通过 `MCUI_MASTER_IMAGE` 固定镜像版本或摘要。使用默认标签更新时，先执行 `docker compose pull`，再执行 `docker compose up -d`。

`master-data` 卷保存面板数据库、任务和签发账本、发布清单验收状态以及两套签发私钥。升级保留该卷。备份时停止主控并备份整个卷，恢复时保留一致的数据库与密钥。Compose 默认由同一进程使用两套密钥，独立签发进程的部署方式见[高级签发配置](./phase-3-approval.md)。

容器内的 chrony 通过 Cloudflare NTS 检查宿主机时间，需要出站 TCP 4460 和 UDP 123。宿主机应保持时钟同步。容器启动后，主控等到 chrony 积累足够的认证样本，并确认时钟误差在允许范围内，才签发任务。

若初始密码丢失且尚未绑定 MFA，使用当前镜像对同一个卷运行恢复命令。

```sh
docker compose stop master
docker compose run --rm --no-deps master \
  -db /var/lib/mcui-master/mcui.db -recover-initial-admin
docker compose up -d
```

## HTTPS 接入

### Compose 自带 HTTPS

下载同一 Release 的 `compose.https.yaml`。让域名指向主控，并开放 TCP 80 和 443。Caddy 自动申请和续期证书，面板通过该域名生成 Agent 安装命令。将以下变量加入部署目录的 `.env`。

```dotenv
MCUI_DOMAIN=panel.example.net
```

```sh
docker compose -f compose.yaml -f compose.https.yaml up -d
```

通过该域名访问面板，添加节点后复制安装命令，在 Debian amd64 或 arm64 的 systemd 节点执行。安装命令从 GitHub 下载同版本的 `install-mcui-agent.sh`，核验镜像内配套的 SHA-256，再传入该部署的公钥并完成注册。

### 反向代理

设置 `MCUI_PUBLIC_URL=https://panel.example.net` 和 `MCUI_HTTPS_PROXY_PEER`。后者是 Master 实际看到的本地或私有代理连接 IP，例如原生部署的 `127.0.0.1`，或宿主机转发到 Compose 时的网桥网关。原生部署写入 `panel.env` 后重启服务，Compose 从部署环境读取变量后重建容器。

代理启用 TLS 1.3 并覆盖转发头。以下是 Nginx HTTPS 虚拟主机中的转发配置。

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host panel.example.net;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

Master 核对连接 IP、Host 和协议头，按配置的外部 HTTPS 地址校验 Origin 并设置 Secure 会话 Cookie。启用反代后，通过配置的 HTTPS 地址访问。对于私有代理连接，限制其他主机对上游端口的访问。

### 直连 TLS

将完整证书链和服务账号可读的私钥路径分别配置为 `MCUI_TLS_CERT` 和 `MCUI_TLS_KEY`，并用 `MCUI_LISTEN` 显式选择监听地址。私钥仅授予服务账号读权限。原生部署重启服务后生效。Compose 直连 TLS 通过部署覆盖文件将证书只读挂载进容器，设置这两个变量，并按需要显式配置宿主机监听地址。直连与反代各选一个。

使用私有 PKI 时，通过 `MCUI_AGENT_INSTALLER_MASTER_CA` 指定供 Agent 使用的 CA PEM 路径。Compose 使用只读文件挂载。已有独立签发服务的部署可通过覆盖文件使用原启动参数和密钥，省去新镜像默认的 `-managed` 参数，并保留原任务数据库。将旧节点迁入自动签发部署前，需要完成节点信任轮换。[Agent 安装与迁移](./phase-1-operations.md)

## 验证记录

2026-11-21，在 `ro` 的 Debian 13 amd64 隔离检出使用 Go 1.27.4、Node.js 26.13.1、pnpm 12.17.0 验证以下提交。

| 提交 | 检查结果 |
|---|---|
| `fb5fa11` | 完整静态检查、Master 和 SQLite 竞态测试、安装包构建及摘要校验通过。核对 amd64/arm64 ELF 和面板静态资源。用包内 amd64 程序启动临时 systemd 服务，验证单次凭据输出、首次换密、TOTP MFA、直连 TLS 1.3、Secure Cookie 和重启保留管理员。 |
| `624a5b5` | 完整静态检查、节点与检查点定向竞态测试、安装包构建及摘要校验通过。验证旧库索引迁移、摘要查询命中索引、心跳仅更新目标节点、拒绝轮换或禁用后的凭据。 |

使用 Docker Compose 5.5.1 在隔离项目中从 `fb5fa11` 镜像升级到 `624a5b5`。验证默认回环端口、非 root 和只读容器运行、首次启动凭据输出、首次换密与 MFA。升级后沿用原 SQLite 卷和管理员。用 TLS 1.3 测试反代验证外部 Origin、Secure Cookie，以及绕过反代的直接请求被拒绝。

2026-11-24，在 `ro` 使用隔离 Compose 项目、临时发布签名和 Caddy 测试 CA，构建并核验 amd64 和 arm64 安装制品。验证主控启动与密钥持久化、HTTPS 换密与 MFA、面板生成固定 GitHub 版本地址和摘要、节点注册 API，以及经 Cloudflare NTS 校时后的状态任务签发和投递。公开下载和正式 Core 安装验收随首个生产 Release 完成。
