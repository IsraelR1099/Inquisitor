FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive \
	FTP_USER=foo \
	FTP_PASS=bar

RUN apt-get update && apt-get install -y \
    openssh-server \
    vsftpd \
    iproute2 \
    inetutils-ping \
    dsniff \
    sudo \
    vim \
    tcpdump \
	git \
	gcc \
	make \
	ftp \
	libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash arp-user && \
    echo 'arp-user:123' | chpasswd && \
    adduser arp-user sudo

COPY script.sh /home/arp-user
COPY arp.c utils.c signals.c set_headers.c sniffer_ftp.c Makefile /home/arp-user
COPY inquisitor.h /home/arp-user

COPY [ "/src/vsftpd.conf", "/etc" ]
COPY [ "/src/docker_entrypoint.sh", "/" ]
RUN chmod +x /docker_entrypoint.sh

RUN mkdir /var/run/sshd
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
RUN echo 'arp-user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers


EXPOSE 20/tcp 21/tcp 40000-40009/tcp

ENTRYPOINT [ "/docker_entrypoint.sh" ]
