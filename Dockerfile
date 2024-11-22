FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

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
COPY arp.c utils.c signals.c /home/arp-user
COPY inquisitor.h /home/arp-user

RUN mkdir /var/run/sshd
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
RUN echo 'arp-user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN echo 'listen=YES' >> /etc/vsftpd.conf && \
    echo 'anonymous_enable=NO' >> /etc/vsftpd.conf && \
    echo 'local_enable=YES' >> /etc/vsftpd.conf && \
    echo 'write_enable=YES' >> /etc/vsftpd.conf && \
    echo 'local_umask=022' >> /etc/vsftpd.conf && \
    echo 'chroot_local_user=YES' >> /etc/vsftpd.conf && \
    echo 'allow_writeable_chroot=YES' >> /etc/vsftpd.conf && \
    echo 'pasv_min_port=40000' >> /etc/vsftpd.conf && \
    echo 'pasv_max_port=40005' >> /etc/vsftpd.conf && \
    echo 'pasv_address=127.0.0.1' >> /etc/vsftpd.conf

EXPOSE 22 21

CMD ["bash", "-c", "service ssh start && tail -f /dev/null"]
