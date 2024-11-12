#!/bin/bash

container_ids=$(docker ps -q)

for container_id in $container_ids; do
		name=$(docker inspect --format='{{.Name}}' $container_id | sed 's/^\///')
		ip_addr=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $container_id)
		mac_address=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' $container_id)
		echo "Container ID: $container_id"
		echo "Name: $name"
		echo "IP Address: $ip_addr"
		echo "MAC Address: $mac_address"
		echo "---------------------------------"
done
