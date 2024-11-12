apt update && \
		apt install -y
echo 'listen=YES' >> /etc/vsftpd.conf && \
echo 'anonymous_enable=NO' >> /etc/vsftpd.conf && \
echo 'local_enable=YES' >> /etc/vsftpd.conf && \
echo 'write_enable=YES' >> /etc/vsftpd.conf && \
echo 'local_umask=022' >> /etc/vsftpd.conf && \
echo 'chroot_local_user=YES' >> /etc/vsftpd.conf && \
echo 'allow_writeable_chroot=YES' >> /etc/vsftpd.conf && \
echo 'pasv_min_port=40000' >> /etc/vsftpd.conf && \
echo 'pasv_max_port=40005' >> /etc/vsftpd.conf && \
echo 'pasv_address=127.0.0.1' >> /etc/vsftpd.conf

service ssh start && \
service vsftpd start
