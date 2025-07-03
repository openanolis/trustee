#!/bin/bash

# Create log directory
mkdir -p /opt/trustee/logs
cp -r /etc/trustee.bak/* /etc/trustee/

# Define log rotation function
setup_log_rotation() {
  service_name=$1
  log_file="/opt/trustee/logs/${service_name}.log"
  
  # Create an empty log file (if it doesn't exist)
  touch $log_file
  
  # Create logrotate configuration
  cat > /etc/logrotate.d/trustee-${service_name} << EOF
$log_file {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        kill -USR1 \$(cat /opt/trustee/logs/${service_name}.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
}

# Setup log rotation for each service
for service in rvps as as-restful kbs trustee-gateway trustee-frontend nginx; do
  setup_log_rotation $service
done

# Start RVPS service
start_rvps() {
  echo "Starting RVPS service..."
  nohup /usr/bin/rvps --config /etc/trustee/rvps.json --address 127.0.0.1:50003 > >(tee -a /opt/trustee/logs/rvps.log) 2>&1 &
  echo $! > /opt/trustee/logs/rvps.pid
  echo "RVPS service started, PID: $(cat /opt/trustee/logs/rvps.pid)"
}

# Start AS service
start_as() {
  echo "Starting AS service..."
  nohup /usr/bin/grpc-as --socket 0.0.0.0:50004 --config-file /etc/trustee/as-config.json > >(tee -a /opt/trustee/logs/as.log) 2>&1 &
  echo $! > /opt/trustee/logs/as.pid
  echo "AS service started, PID: $(cat /opt/trustee/logs/as.pid)"
}

# Start AS-Restful service
start_as_restful() {
  echo "Starting AS-Restful service..."
  nohup /usr/bin/restful-as --socket 0.0.0.0:50005 --config-file /etc/trustee/as-config.json > >(tee -a /opt/trustee/logs/as-restful.log) 2>&1 &
  echo $! > /opt/trustee/logs/as-restful.pid
  echo "AS-Restful service started, PID: $(cat /opt/trustee/logs/as-restful.pid)"
}

# Start KBS service
start_kbs() {
  echo "Starting KBS service..."
  nohup /usr/bin/kbs --config-file /etc/trustee/kbs-config.toml > >(tee -a /opt/trustee/logs/kbs.log) 2>&1 &
  echo $! > /opt/trustee/logs/kbs.pid
  echo "KBS service started, PID: $(cat /opt/trustee/logs/kbs.pid)"
}

# Start Trustee-Gateway service
start_trustee_gateway() {
  echo "Starting Trustee-Gateway service..."
  nohup /usr/bin/trustee-gateway --config /etc/trustee/gateway.yml > >(tee -a /opt/trustee/logs/trustee-gateway.log) 2>&1 &
  echo $! > /opt/trustee/logs/trustee-gateway.pid
  echo "Trustee-Gateway service started, PID: $(cat /opt/trustee/logs/trustee-gateway.pid)"
}

# Start Trustee-Frontend service
start_trustee_frontend() {
  echo "Starting Trustee-Frontend service..."
  nohup /usr/sbin/nginx -g "daemon off;" > >(tee -a /opt/trustee/logs/nginx-trustee-frontend.log) 2>&1 &
  echo $! > /opt/trustee/logs/nginx-trustee-frontend.pid
  echo "Trustee-Frontend service started, PID: $(cat /opt/trustee/logs/nginx-trustee-frontend.pid)"
}

# Start services in sequence
start_rvps
sleep 2
start_as
sleep 2
start_as_restful
sleep 2
start_kbs
sleep 1
start_trustee_gateway
sleep 1
start_trustee_frontend

echo "All services started. Log files are located in /opt/trustee/logs/ directory"

# Check service status
check_services() {
  echo "Checking service status..."
  for service in rvps as as-restful kbs trustee-gateway nginx-trustee-frontend; do
    if [ -f "/opt/trustee/logs/${service}.pid" ]; then
      pid=$(cat /opt/trustee/logs/${service}.pid)
      if ps -p $pid > /dev/null; then
        echo "$service is running, PID: $pid"
      else
        echo "$service is not running!"
      fi
    else
      echo "$service PID file does not exist!"
    fi
    
  done
}

check_services

# Add monitoring loop to keep the container main process running
trap 'echo "Signal received, exiting..."; exit 0' SIGTERM SIGINT
while true; do
  # Monitor service status every 60 seconds
  sleep 60
  check_services
done