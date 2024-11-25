#!/bin/bash

if ! getent group $FTP_USER > /dev/null 2>&1; then
	groupadd $FTP_USER
	echo "Group $FTP_USER created."
else
	echo "Group $FTP_USER already exists."
fi

if ! id -u $FTP_USER > /dev/null 2>&1; then
	useradd --home /home/$FTP_USER --shell /bin/false --gid $FTP_USER $FTP_USER
	echo "User $FTP_USER created."
else
	echo "User $FTP_USER already exists."
fi

# Set the password for the user
if id -u $FTP_USER > /dev/null 2>&1; then
	echo "$FTP_USER:$FTP_PASS" | chpasswd
else
	echo "Skipping password setup as user $FTP_USER does not exist."
fi

# Create the home directory
if [ ! -d /home/$FTP_USER ]; then
	mkdir -p /home/$FTP_USER
fi

# Set the owner of the home directory
if id -u $FTP_USER > /dev/null 2>&1; then
	chown -R $FTP_USER:$FTP_USER /home/$FTP_USER
else
	echo "Skipping chown as user $FTP_USER does not exist."
fi

# Prepare vsftpd logs
touch /var/log/vsftpd.log
touch /var/log/xferlog

# Tail logs in the background
tail -f /var/log/vsftpd.log | tee /dev/stdout &
tail -f /var/log/xferlog | tee /dev/stdout &

# Start vsftpd
echo "Starting vsftpd..."
#exec /usr/sbin/vsftpd
tail -f /dev/null
