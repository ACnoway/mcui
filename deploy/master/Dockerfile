FROM debian:13-slim
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 65532 -g 65532 -m 0700 /var/lib/mcui-master
COPY ${TARGETARCH}/mcui-panel /usr/local/bin/mcui-panel
COPY web/ /opt/mcui/web/
USER 65532:65532
ENV MCUI_LISTEN=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mcui-panel"]
CMD ["-container-http", "-single-admin", "-db", "/var/lib/mcui-master/mcui.db", "-web", "/opt/mcui/web", "-core-backup-dir", "/var/lib/mcui-master/core-backups"]
