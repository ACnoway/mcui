FROM debian:13-slim
ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/ACnoway/mcui"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates chrony \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 65532 -g 65532 -m 0700 /var/lib/mcui-master
COPY ${TARGETARCH}/mcui-panel /usr/local/bin/mcui-panel
COPY web/ /opt/mcui/web/
COPY release/ /opt/mcui/release/
COPY chrony.conf /opt/mcui/chrony.conf
COPY container-entrypoint.sh /opt/mcui/container-entrypoint.sh
USER 65532:65532
ENV MCUI_LISTEN=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/opt/mcui/container-entrypoint.sh"]
CMD ["-managed", "-container-http", "-single-admin", "-db", "/var/lib/mcui-master/mcui.db", "-web", "/opt/mcui/web", "-core-backup-dir", "/var/lib/mcui-master/core-backups"]
