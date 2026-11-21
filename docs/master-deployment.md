# 单管理员 Master 部署

本文覆盖当前源码的 Linux systemd 安装包、Compose 镜像、首次登录与 HTTPS。旧部署仍按[阶段 1 运维手册](./phase-1-operations.md)维护。节点任务和远程 Xray 的剩余集成见[阶段 3 进度](./phase-3-progress.md)。

## 构建安装包和镜像

在安装了[项目指定工具链](./development-baseline.md)的 Linux 主机上构建。输出包含支持 amd64 和 arm64 的 Master 安装程序、SHA-256 文件，以及镜像构建上下文。

```sh
bash scripts/build-master-release.sh /tmp/mcui-master-release
docker buildx build --load -f deploy/master/Dockerfile \
  -t mcui-master:local /tmp/mcui-master-release/image
```

发布时将版本化安装程序和校验材料放到项目 GitHub Releases，将同一构建产物生成的镜像以版本及镜像摘要标识。安装前从可信发布渠道核对摘要。生产发布状态见[阶段 3 发布手册](./phase-3-release.md#生产发布验收)。

## systemd 安装

在运行 systemd 的 Linux amd64 或 arm64 主机上，使用带有效系统 CA 的环境。将已核对的 `SHA256SUMS` 和安装程序放在同一目录。

```sh
sha256sum --check SHA256SUMS && sudo bash ./install-mcui-master.sh
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

```sh
export MCUI_MASTER_IMAGE=mcui-master:local
docker compose up -d
docker compose logs master
```

首次启动的容器日志包含初始凭据。宿主机端口默认仅绑定 `127.0.0.1:8080`；可用 `MCUI_MASTER_PORT` 调整端口。容器使用非 root UID 和只读根文件系统，`master-data` 卷保存 SQLite 和缓存。更新 `MCUI_MASTER_IMAGE` 后重新执行 `docker compose up -d`，沿用同一数据卷。上线使用已核验的版本化镜像。

若初始密码丢失且尚未绑定 MFA，使用当前镜像对同一个卷运行恢复命令。

```sh
docker compose stop master
docker compose run --rm --no-deps master \
  -db /var/lib/mcui-master/mcui.db -recover-initial-admin
docker compose up -d
```

## HTTPS 接入

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

生成 Agent 安装命令仍需提供已批准的安装程序 HTTPS URL、SHA-256 摘要及节点任务信任材料。[Agent 安装与迁移](./phase-1-operations.md)
