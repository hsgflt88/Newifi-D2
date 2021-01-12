#!/bin/bash
# 升级安装软件
GREEN="\033[32m\033[01m"
# 删除软件源注释和空格行备份
sed -i '/^#/d' /etc/apt/sources.list
sed -i '/^\s*$/d' /etc/apt/sources.list
rm -rf /etc/apt/sources.list.bak
cp -R /etc/apt/sources.list /etc/apt/sources.list.bak
# 升级安装软件 dpkg-dev
#rm -rf /var/lib/dpkg/lock
#rm -rf /var/cache/apt/archives/lock
apt update
apt -y upgrade
#dpkg --configure -a
apt install -y lsof gzip bash gperf libcap2-bin sudo gawk flex bison
apt install -y net-tools psmisc cron openssl libc6-dev parted xfsprogs xdg-utils
apt install -y libcunit1-dev libev-dev libjansson-dev libc-ares-dev libjemalloc-dev cython
apt install -y gnutls-dev libpcap-dev libevent-dev python3-dev zlib1g-dev zlib1g libtirpc-dev
apt install -y unzip libssl-dev libtool-bin libbz2-dev bzip2 gcc g++ make libpcre3-dev
apt install -y dnsutils curl libcurl3-dev vim socat mtr dirmngr sysstat ethtool
apt install -y python3-setuptools libxpm-dev build-essential libmpfr-dev mtr sed cmake wget git libkeyutils-dev zip
apt install -y libsystemd-dev libnfsidmap-dev libsqlite3-dev libblkid-dev pkg-config automake autoconf libxslt1-dev
apt install -y libnghttp2-dev libtiff5-dev libpng-dev libfontconfig1-dev libwebp-dev libharfbuzz-dev gtk-doc-tools
apt install -y libsctp-dev libperl-dev libatomic-ops-dev libgeoip-dev libgoogle-perftools-dev libfribidi-dev
apt install -y resolvconf
apt -y autoremove
apt clean
# 设置SSH端口
sed -i 's@Port 22@#Port 22@' /etc/ssh/sshd_config
cat >>/etc/ssh/sshd_config<<EOF
Port 20022
Protocol 2
#PermitRootLogin yes
ClientAliveInterval 30
ClientAliveCountMax 6
EOF
# 设定时区
timedatectl set-timezone "Asia/Shanghai"
# 修改主机名
hostnamectl --static set-hostname localhost
# 删除SSH登录显示信息
sed -i '3,$d' /etc/update-motd.d/10-help-text
# 开启BBR / 转发 / 修改ulimit值
cat >>/etc/sysctl.conf<<EOF
fs.file-max = 65536
net.ipv4.ip_forward = 0
net.ipv4.tcp_fastopen = 3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
# 修改ulimit值
cat >>/etc/security/limits.conf<<EOF
*      soft  nproc   65536
*      hard  nproc   65536
*      soft  nofile  65536
*      hard  nofile  65536
root   soft  nproc   65536
root   hard  nproc   65536
root   soft  nofile  65536
root   hard  nofile  65536
EOF
# 搭建FTP服务
mkdir -p /home/yblhx/rj
cd /home/yblhx/rj
groupadd -g 1001 yblhx
useradd  -c System_User -d /home/yblhx -g yblhx -s /bin/false -u 1001 yblhx
cat >>/etc/shells<<EOF
/bin/false
EOF
chown -R yblhx.yblhx /home/yblhx
chown -R yblhx.yblhx /home/yblhx/rj
wget https://github.com/jedisct1/pure-ftpd/releases/download/1.0.49/pure-ftpd-1.0.49.tar.gz
tar zxvf pure-ftpd-1.0.49.tar.gz
cd pure-ftpd-1.0.49
./configure --prefix=/usr --sysconfdir=/etc/pure-ftpd --with-everything --with-language=simplified-chinese
make
make install
cd /home/yblhx/rj
cp -R /etc/pure-ftpd/pure-ftpd.conf /etc/pure-ftpd/pure-ftpd.conf.bak
sed -i '/^#/d' /etc/pure-ftpd/pure-ftpd.conf
sed -i '/^\s*$/d' /etc/pure-ftpd/pure-ftpd.conf
sed -i '25d' /etc/pure-ftpd/pure-ftpd.conf
sed -i '18d' /etc/pure-ftpd/pure-ftpd.conf
sed -i '9d' /etc/pure-ftpd/pure-ftpd.conf
sed -i '2d' /etc/pure-ftpd/pure-ftpd.conf
cat >>/etc/pure-ftpd/pure-ftpd.conf<<EOF
MaxDiskUsage                 99
MinUID                       1000
BrokenClientsCompatibility   yes
NoAnonymous                  yes
TrustedGID                   1001
Bind                         20021
PassivePortRange             50000 50003
EOF
cat >>/lib/systemd/system/pure-ftpd.service<<EOF
[Unit]
Description=Pure-FTPd FTP server
After=network.target

[Service]
Type=forking
PIDFile=/run/pure-ftpd.pid
ExecStart=/usr/sbin/pure-ftpd /etc/pure-ftpd/pure-ftpd.conf

[Install]
WantedBy=multi-user.target
EOF
sleep 2
systemctl enable pure-ftpd.service
# 添加环境变量
cat >>/etc/profile<<EOF
#PATH Xray / v2ray / Nginx
export PATH=\$PATH:/usr/xray:/usr/v2ray:/home/service/nginx/sbin
EOF
cat >>/etc/profile<<EOF
#PATH GO
export GOPATH=/home/yblhx/rj
export GOROOT=/usr/local/go
export PATH=\$PATH:\$GOROOT/bin
export GOHOSTARCH="amd64"
export GOHOSTOS="linux"
export GOARCH="amd64"
export GOOS="linux"
export GOTOOLDIR=/usr/local/go/pkg/linux_amd64
EOF
# 手动安装GO
cd /home/yblhx/rj
wget https://golang.google.cn/dl/go1.15.6.linux-amd64.tar.gz
tar zxvf go1.15.6.linux-amd64.tar.gz
mv go /usr/local
# 安装xray
wget https://github.com/XTLS/Xray-core/releases/download/v1.2.1/Xray-linux-64.zip
rm -rf /usr/xray
unzip -o -d /usr/xray Xray-linux-64.zip
rm -rf /etc/xray
mkdir -p /etc/xray
rm -rf /var/log/xray
chmod +x /usr/xray/xray
# 安装v2ray
wget https://github.com/v2fly/v2ray-core/releases/download/v4.34.0/v2ray-linux-64.zip
rm -rf /usr/v2ray
unzip -o -d /usr/v2ray v2ray-linux-64.zip
rm -rf /etc/v2ray
mkdir -p /etc/v2ray
rm -rf /var/log/v2ray
mkdir -p /var/log/v2ray
chmod +x /usr/v2ray/v2ray
chmod +x /usr/v2ray/v2ctl
# 创建xray启动脚本
cat <<EOF >/lib/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/xray/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
# 创建v2ray启动脚本
cat <<EOF >/lib/systemd/system/v2ray.service
[Unit]
Description=V2Ray Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/v2ray/v2ray -config /etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=500
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
# 创建Xray VLESS-TLS-Nginx服务端配置
cat <<EOF >/etc/xray/config.json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [{
    "port": 6900,
    "listen":"127.0.0.1",
    "protocol": "vless",
    "settings": {
      "clients": [{
        "id": "e3d8a113-f4f0-4a63-9bc9-288ccc1ff323",
        "level": 0,
        "email": "test@blank.blank"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "ws",
      "security": "none",
      "wsSettings": {
        "path": "/r98cnf9h"
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom"
  }]
}
EOF
cp -R /etc/xray/config.json /etc/v2ray/config.json
systemctl enable v2ray.service
# 安装编译NGINX
cd /home/yblhx/rj
git clone https://github.com/ImageOptim/libimagequant.git
cd libimagequant
./configure --prefix=/usr
make
make install
cd /home/yblhx/rj
git clone https://github.com/HOST-Oman/libraqm.git
cd libraqm
./autogen.sh
./configure --prefix=/usr
make
make install
cd /home/yblhx/rj
wget https://github.com/libgd/libgd/releases/download/gd-2.3.0/libgd-2.3.0.tar.gz
rm -rf libgd-2.3.0
tar zxvf libgd-2.3.0.tar.gz
cd libgd-2.3.0
./configure --prefix=/usr --with-png --with-freetype --with-jpeg --with-fontconfig --with-tiff --with-xpm --with-liq --with-webp --with-zlib
make
make install
cd /home/yblhx/rj
wget http://washitake.com/mail/exim/mirror/pcre/pcre-8.44.tar.gz
wget http://www.zlib.net/zlib-1.2.11.tar.gz
tar zxvf pcre-8.44.tar.gz
tar zxvf zlib-1.2.11.tar.gz
wget https://www.openssl.org/source/openssl-1.1.1i.tar.gz
tar zxvf openssl-1.1.1i.tar.gz
wget http://nginx.org/download/nginx-1.18.0.tar.gz
rm -rf nginx-1.18.0
tar zxvf nginx-1.18.0.tar.gz
cd nginx-1.18.0
./configure --prefix=/home/service/nginx \
--with-debug --with-openssl=../openssl-1.1.1i \
--with-zlib=../zlib-1.2.11 --with-pcre=../pcre-8.44 --with-pcre-jit \
--with-openssl-opt="enable-tls1_3 enable-tls1_2 enable-tls1 enable-ssl enable-ssl2 enable-ssl3 enable-ec_nistp_64_gcc_128 shared threads zlib-dynamic sctp" \
--with-mail=dynamic --with-mail_ssl_module --with-stream=dynamic --with-stream_ssl_module \
--with-stream_realip_module --with-stream_geoip_module=dynamic --with-stream_ssl_preread_module \
--with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module \
--with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_geoip_module=dynamic \
--with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module \
--with-http_gzip_static_module --with-http_auth_request_module --with-http_random_index_module --with-http_secure_link_module \
--with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic \
--with-libatomic --with-compat --with-cpp_test_module --with-google_perftools_module --with-file-aio \
--with-threads --with-poll_module --with-select_module --with-cc-opt="-Wno-error -g0 -O3"
make
make install
cd /home/yblhx/rj
# 添加Nginx启动脚本
cat <<EOF >/lib/systemd/system/nginx.service
[Unit]
Description=nginx web server and proxy server
Documentation=man:nginx(8)
After=network.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/bin/rm -rf /home/service/nginx/unixsocks_temp
ExecStartPre=/bin/mkdir /home/service/nginx/unixsocks_temp
ExecStartPre=/bin/chmod 755 /home/service/nginx/unixsocks_temp
ExecStartPre=/bin/rm -rf /home/service/nginx/tcmalloc_temp
ExecStartPre=/bin/mkdir /home/service/nginx/tcmalloc_temp
ExecStartPre=/bin/chmod 777 /home/service/nginx/tcmalloc_temp
ExecStartPre=/home/service/nginx/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/home/service/nginx/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/home/service/nginx/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
ExecStopPost=/bin/rm -rf /home/service/nginx/tcmalloc_temp
ExecStopPost=/bin/rm -rf /home/service/nginx/unixsocks_temp
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
systemctl enable nginx.service
cat <<EOF >/home/service/nginx/conf/upstream.conf
  client_header_timeout         60;
  client_header_buffer_size     32k;
  large_client_header_buffers   4 32k;
  client_body_timeout           120;
  client_max_body_size          300m;
  client_body_buffer_size       128k;
  reset_timedout_connection     on;
  send_timeout                  60;
  fastcgi_connect_timeout       300;
  fastcgi_send_timeout          300;
  fastcgi_read_timeout          300;
  fastcgi_buffer_size           64k;
  fastcgi_buffers               4 64k;
  fastcgi_busy_buffers_size     128k;
  fastcgi_temp_file_write_size  256k;
EOF
cat <<EOF >/home/service/nginx/conf/gzip.conf
  gzip on;
  gzip_disable "MSIE [1-6].(?!.*SV1)";
  gzip_http_version 1.1;
  gzip_vary on;
  gzip_proxied any;
  gzip_min_length 1000;
  gzip_buffers 16 8k;
  gzip_comp_level 6;
  gzip_types text/css text/xml text/plain text/javascript application/javascript application/json application/xml application/rss+xml application/xhtml+xml;
EOF
cat <<EOF >/home/service/nginx/conf/ssl.conf
  ssl_certificate             /home/service/ssl/ipchina.tk.crt;
  ssl_certificate_key         /home/service/ssl/ipchina.tk.key;
  ssl_session_cache           shared:SSL:50m;
  ssl_session_timeout         1d;
  ssl_ciphers                 HIGH:!aNULL:!MD5;
  ssl_protocols               TLSv1.1 TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers   on;
EOF
cat <<EOF >/home/service/nginx/conf/ssl1.3.conf
  ssl_certificate             /home/service/ssl/mmm.ipchina.tk.crt;
  ssl_certificate_key         /home/service/ssl/mmm.ipchina.tk.key;
  ssl_session_cache           shared:SSL:50m;
  ssl_session_timeout         1d;
  ssl_ciphers                TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
  ssl_protocols               TLSv1.3;
  ssl_prefer_server_ciphers   on;
  # 开启1.3 0-RTT
  ssl_early_data      on;
  ssl_stapling        on;
  ssl_stapling_verify on;
EOF
cat <<EOF >/home/service/nginx/conf/ws_tls.conf
  location /r98cnf9h {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:6900;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$http_host;
  }
EOF
cat <<EOF >/home/service/nginx/conf/nginx.conf
user                   root root;
worker_processes       auto;
error_log              logs/error.log crit;
pid                    /run/nginx.pid;
worker_rlimit_nofile   65536;
google_perftools_profiles /home/service/nginx/tcmalloc_temp/tcmalloc;

events {
  use                 epoll;
  worker_connections  65536;
  multi_accept        on;
}

http {
  include       mime.types;
  default_type  application/octet-stream;
  server_names_hash_bucket_size   256;

  access_log            off;
  server_tokens         off;
  sendfile              on;
  sendfile_max_chunk    512k;
  tcp_nopush            on;
  tcp_nodelay           on;
  keepalive_timeout     65;
  keepalive_requests    100;

  include upstream.conf;
  include gzip.conf;
  include vhosts.conf;
  include xray.conf;
}
EOF
cat <<EOF >/home/service/nginx/conf/xray.conf
# xray
server {
  listen       443 ssl http2;
  server_name  mmm.ipchina.tk;
  root         /home/service/xray;
  index        index.html index.htm;
  include      ssl1.3.conf;
  include      ws_tls.conf;
}
EOF
cat <<EOF >/home/service/nginx/conf/vhosts.conf
# web
server{
  listen       443 ssl http2;
  server_name  ipchina.tk;
  index        index.html index.htm;
  root         /home/yblhx/www;
  include      ssl.conf;
}
EOF
mkdir -p /home/yblhx/www
chown -R yblhx.yblhx /home/yblhx/www
wget https://github.com/hsgflt88/Newifi-D2/raw/main/index1.zip
unzip -o -d /home/service/xray index1.zip
chown -R yblhx.yblhx /home/service/xray
# 安装测速及回程线路检测
cd /home/yblhx/rj
cat >>/etc/profile<<EOF
#PATH Besttrace / NPM
export PATH=\$PATH:/usr/besttrace:/usr/nodejs/bin
EOF
wget https://nodejs.org/dist/v15.5.1/node-v15.5.1.tar.xz
tar -xvf node-v15.5.1.tar.xz
mv node-v15.5.1-linux-x64 /usr/nodejs
source /etc/profile
sleep 3
npm install --global speed-test
wget https://github.com/zhucaidan/BestTrace-Linux/raw/master/besttrace4linux.zip
unzip -o -d /usr/besttrace besttrace4linux.zip
chmod +x /usr/besttrace/besttrace
chmod +x /usr/besttrace/besttrace32
# 生成证书
curl https://get.acme.sh|sh
mkdir -p /home/service/ssl
/root/.acme.sh/acme.sh --issue -d ipchina.tk --standalone -k ec-256
/root/.acme.sh/acme.sh --issue -d mmm.ipchina.tk --standalone -k ec-256
sleep 5
/root/.acme.sh/acme.sh --installcert -d ipchina.tk --fullchainpath /home/service/ssl/ipchina.tk.crt --keypath /home/service/ssl/ipchina.tk.key --ecc
/root/.acme.sh/acme.sh --installcert -d mmm.ipchina.tk --fullchainpath /home/service/ssl/mmm.ipchina.tk.crt --keypath /home/service/ssl/mmm.ipchina.tk.key --ecc
rm -rf /home/yblhx/rj/*
# 禁用无用服务
systemctl disable motd-news.timer
systemctl disable motd-news.service
systemctl disable apt-daily.service
systemctl disable apt-daily.timer
systemctl disable apt-daily-upgrade.timer
systemctl disable apt-daily-upgrade.service
systemctl disable redis-server.service
systemctl disable systemd-resolved.service
# 卸载旧版本内核
apt purge -y linux-headers-5.4.0-28
apt purge -y linux-headers-5.4.0-28-generic
apt purge -y linux-modules-5.4.0-28-generic
apt purge -y linux-image-4.15.0-99-generic
apt purge -y linux-modules-4.15.0-99-generic
# 安装配置防火墙
update-grub
apt install -y ufw
sudo ufw allow 20021:20022/tcp
sudo ufw allow 50000:50003/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 80/udp
sudo ufw allow 443/udp
sudo ufw allow 8443/tcp
sudo ufw allow 8443/udp
resize2fs /dev/vda1
rm -rf /home/*.sh
echo -e "
${GREEN}====================安装成功====================

${GREEN}        请设定 yblhx 用户的密码并重启

${GREEN}      yblhx用户设定密码命令 passwd yblhx

${GREEN}====================谢谢使用===================="