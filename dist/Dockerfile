FROM alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest

ARG TRUSTEE_VERSION=1.4.2

WORKDIR /usr/src/

RUN yum install -y trustee-${TRUSTEE_VERSION} trustee-frontend-${TRUSTEE_VERSION} procps-ng

COPY start.sh /usr/bin/start.sh

VOLUME /opt/trustee
VOLUME /etc/trustee

EXPOSE 8081
EXPOSE 8082

CMD ["/usr/bin/start.sh"]