# dimc
베트남 관리자

# Ubuntu LEMP-stack 설치 스크립트 설명

* 이 스택에서 다루는 방법은 22.04 LTS (GNU/Linux 5.15.0-1011-aws x86_64) 에서 검증된 방식입니다.
* 가장 기본적인 스탭으로 타 운영체제 세팅시에도 명령어조합이 조금 차이날 뿐 거의 동일한 방법으로 가능합니다.
* 모든 명령어는 root 권한의 상태에서 실행한 결과입니다. (필요할 경우 유저 변경을 수행하는 부분은 따로 표시합니다.)
* 이 스택을 모두 설치하는데 소요되는 시간은 약 10분 내외입니다.

## 0. 기본 호스트 설정

### root 권한 허용
> jang 사용자의 sudo 사용시 비밀번호를 묻지 않는다.
```bash
USERID="jang"
chmod 700 /etc/sudoers && \
echo "
jang ALL=(ALL) NOPASSWD: ALL
" >> /etc/sudoers && \
chmod 440 /etc/sudoers
```

### ssh 접속시 비밀번호 허용
> ssh 접속시 비밀번호를 이용한 인증을 허용한다.(로컬환경에서는 셋팅 불필요)
```bash
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config && \
service ssh restart
```

### root 비밀번호 변경
> "root:**password**" 부분 password 수정

```bash
echo "root:1234"|chpasswd
```

### OS 패키지 업데이트 및 업그레이드 및 불필요한 패키지 자동 삭제
```bash
export DEBIAN_FRONTEND=noninteractive && \
apt-get update && \
apt-get -o Dpkg::Options::="--force-confnew" -fuy dist-upgrade && \
apt -y autoremove
```

### 서버 시간 변경
> 한국 시간으로 서버 시간 설정을 변경하고 싶을 때 수행합니다.(로컬환경에서는 셋팅 불필요)
```bash
TIMEZONE="Asia/Seoul"
timedatectl set-timezone $TIMEZONE
```

### hostname 및 hosts
> 실제로 사용 할 도메인으로 서버 호스트 네임을 변경합니다. 내부적으로 도메인 네임을 설정해놓으면 외부 네임서버를 거치지 않고 바로 스크립트등을 수행하기 때문에 설정해 둘 필요가 있습니다.
```bash
DOMAIN="nginx-example.com"
echo "${DOMAIN}" > /etc/hostname
hostname -F /etc/hostname
sed -i "s/127.0.0.1 localhost/127.0.0.1 localhost ${DOMAIN}/" /etc/hosts
```

### 새로운 디스크 마운트
> (로컬환경에서는 셋팅 불필요)
```bash
// 새로 장착된 디스크 확인
fdisk -l

// 파티션 설정
fdisk /dev/sdb
n
p
1
(enter)
(enter)
p
w

// 포멧
mkfs.ext4 /dev/sdb1

// UUID 확인
blkid

// 마운트 포인트 생성
mkdir -p /data

// 마운트 내용 저장
vim /etc/fstab
UUID=3255683f-53a2-4fdf-91cf-b4c1041e2a62 /data ext4 defaults 0 0

// 마운트
mount -a
df -h
```

### 디스크 볼륨 크기 조정 후 파티션 확장
> (로컬환경에서는 셋팅 불필요)
```bash
// 수정된 파티션 확장
growpart /dev/xvdf 1
CHANGED: disk=/dev/xvdf partition=1: start=4096 old: size=16773086,end=16777182 new: size=73396190,end=73400286

// 수정된 파티션 확인
lsblk
NAME    MAJ:MIN RM SIZE RO TYPE MOUNTPOINT
...
xvdf    202:80   0  35G  0 disk
└─xvdf1 202:81   0  35G  0 part

// 파티션 리사이징
resize2fs /dev/xvdf1
```

## 메모리 SWAP 영역 활성화
> 사양이 낮은 인스턴스를 활용할 시 필수적으로 수행하는 편이 좋습니다.(로컬환경에서는 셋팅 불필요)
```bash
// 시스템에서 스왑 정보 확인
swapon --show
NAME        TYPE  SIZE   USED PRIO
/var/swap.1 file 1024M 169.5M   -2

// 4G 스왑 생성
fallocate -l 4G /swapfile && \
chmod 600 /swapfile && \
mkswap /swapfile && \
swapon /swapfile

// 재부팅 후에도 스왑 유지
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

```
## 1. 서버운영에 필요한 필수 프로그램 설치

### zip 파일 압축을 풀기 위한 unzip 설치

```bash
apt-get -y install unzip
```

## 2. Nginx

### Nginx 설치
> 최신버전의 Nginx를 사용하기 위해 저장소를 추가합니다.
```bash
add-apt-repository ppa:ondrej/nginx-mainline
```

> Nginx를 설치합니다.
```bash
apt-get -y install nginx && \
service nginx start
```

버전을 확인해 봅니다.

```bash
nginx -v
nginx version: nginx/1.23.1
```

웹 브라우저로 서버 아이피나 도메인을 통해 접속을 시도해봅시다.

Welcome to nginx!
If you see this page, the nginx web server is successfully installed and working. Further configuration is required.

For online documentation and support please refer to nginx.org.
Commercial support is available at nginx.com.

Thank you for using nginx.

해당 문구의 텍스트 페이지가 나타난다면 Nginx는 문제없이 잘 설치된 상태입니다.
만약 정적인(static) 페이지의 웹 사이트를 운영할 생각이라면 이 상태로 바로 서버를 운영해도 전혀 문제가 없는 상태입니다.

저장경로(/var/www/html)에서 웹사이트를 업로드하고 바로 이용을 하실 수 있습니다.

## 3. PHP-FPM

### php-fpm 8.0 설치
> 최신버전의 php를 사용하기 위해 저장소를 추가합니다.
```bash
add-apt-repository ppa:ondrej/php
```

> php-fpm 8.0을 설치합니다.
```bash
PHPVERSION="8.0"
apt-get -y install php$PHPVERSION-fpm php$PHPVERSION-intl php$PHPVERSION-gd php$PHPVERSION-curl php$PHPVERSION-mbstring php$PHPVERSION-xml php$PHPVERSION-zip php$PHPVERSION-bcmath php$PHPVERSION-gmp && \
sed -i 's/;emergency_restart_threshold = 0/emergency_restart_threshold = 10/' /etc/php/$PHPVERSION/fpm/php-fpm.conf && \
sed -i 's/;emergency_restart_interval = 0/emergency_restart_interval = 1m/' /etc/php/$PHPVERSION/fpm/php-fpm.conf && \
service php$PHPVERSION-fpm start
```

> 버전을 확인해 봅니다.
```bash
php -v
PHP 8.0.22 (cli) (built: Aug 15 2022 09:40:14) ( NTS )
Copyright (c) The PHP Group
Zend Engine v4.0.22, Copyright (c) Zend Technologies
    with Zend OPcache v8.0.22, Copyright (c), by Zend Technologies
```

### composer 설치
```bash
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" && \
php composer-setup.php --filename=composer --install-dir=/usr/local/bin && \
php -r "unlink('composer-setup.php');"
```

## 4. MariaDB
### MariaDB 10.6 설치
> MariaDB 저장소 설치
```bash
sudo apt-get install apt-transport-https curl
sudo curl -o /etc/apt/trusted.gpg.d/mariadb_release_signing_key.asc 'https://mariadb.org/mariadb_release_signing_key.asc'
sudo sh -c "echo 'deb https://mirrors.xtom.jp/mariadb/repo/10.6/ubuntu jammy main' >>/etc/apt/sources.list"
apt-get update
```

```bash
DBROOTPASS="1234"
PHPVERSION="8.0"
MARIADBVERSION="10.6"
debconf-set-selections <<< "mariadb-server-${MARIADBVERSION} mysql-server/root_password password ${DBROOTPASS}"
debconf-set-selections <<< "mariadb-server-${MARIADBVERSION} mysql-server/root_password_again password ${DBROOTPASS}"
apt-get -y install mariadb-server-$MARIADBVERSION mariadb-client-$MARIADBVERSION && \
apt-get -y install php$PHPVERSION-mysql && \
service mariadb start
```

설치가 제대로 되었는지 확인 합니다.

```bash
service mariadb status
● mariadb.service - MariaDB 10.5.8 database server
     Loaded: loaded (/lib/systemd/system/mariadb.service; enabled; vendor preset: enabled)
    Drop-In: /etc/systemd/system/mariadb.service.d
             └─migrated-from-my.cnf-settings.conf
     Active: active (running) since Fri 2021-01-22 15:11:41 KST; 39s ago
       Docs: man:mariadbd(8)
             https://mariadb.com/kb/en/library/systemd/
   Main PID: 14304 (mariadbd)
     Status: "Taking your SQL requests now..."
      Tasks: 12 (limit: 1137)
     Memory: 69.2M
     CGroup: /system.slice/mariadb.service
             └─14304 /usr/sbin/mariadbd
```

### MariaDB 언어셋 설정

최근엔 모바일에서 사용하는 이모지(emoji)등에 대응하기 위해 `utf8`이 아닌 `utf8mb4` 언어셋으로 지정합니다.

```bash
echo "[client]
default-character-set = utf8mb4

[mysql]
default-character-set = utf8mb4

[mysqld]
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
skip-name-resolve
skip-external-locking

## MariaDB 스케줄러
event-scheduler = OFF
sysdate-is-now

back_log = 100
max_connections = 300
max_connect_errors = 999999
# max_connections에 비례해서 사용
thread_cache_size = 50
table_open_cache = 400
wait_timeout = 6000

max_allowed_packet = 32M
max_heap_table_size = 32M
tmp_table_size = 512K

sort_buffer_size = 128K
join_buffer_size = 128K
read_buffer_size = 128K
read_rnd_buffer_size = 128K

query_cache_type = 1
query_cache_size = 32M
query_cache_limit = 2M

group_concat_max_len = 1024

## 마스터 MariaDB 서버에서 레코드 기반 복제를 사용할 때는 READ-COMMITTED 사용 가능
## 복제에 참여하지 않는 MariaDB 서버에서는 READ-COMMITTED 사용 가능
## 그 외에는 반드시 REPEATABLE-READ 로 사용
transaction-isolation = REPEATABLE-READ

## InnoDB 기본 옵션
## InnoDB를 사용하지 않는다면 innodb_buffer_pool_size를 최소화하거나
## InnoDB 스토리지 엔젠을 기동하지 않도록 설정
innodb_buffer_pool_size = 1G

## MyISAM 옵션
## InnoDB를 사용하지 않고 MyISAM만 사용한다면 key_buffer_size를 4GB까지 설정
key_buffer_size = 32M

## 로깅 옵션
slow-query-log = 1
long_query_time = 1

## 복제 옵션
binlog_cache_size = 128K
max_binlog_size = 512M
expire_logs_days = 14
log-bin-trust-function-creators = 1
sync_binlog = 1

lower_case_table_names = 1
query_cache_min_res_unit = 2k
sql_mode = NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION

[mysqldump]
default-character-set=utf8mb4
max_allowed_packet = 32M
" > /etc/mysql/conf.d/mariadb.cnf
service mariadb restart
```
## 5. redis 캐시서버 설치
부가적으로 PHP에서 세션을 이용할 때 디스크 파일이 아닌 캐시를 이용해서 사이트 속도 품질을 올리는 기법이 추천되고 있습니다.
하드디스크 파일보단 메모리 캐시의 I/O가 훨씬 빠르다는 것쯤은 모두 알고 계시지요.
### redis 서버 및 php-redis 연동 설치
```bash
apt-get -y install redis-server && \
apt-get -y install php8.0-redis && \
service redis-server start
```

핑퐁 테스트를 실행해서 redis에 정상적으로 접속이 되는지 확인합니다.
```bash
redis-cli PING
PONG
```

이후 PHP 설정에서 세션 핸들러를 파일이 아닌 redis 서버로 설정할 것입니다.

## 6. Nginx 와 PHP를 연동하는 기본 설정

apache와 달리 Nginx는 PHP 스크립트를 해석하는 모듈을 기본적으로 포함하고 있지 않습니다. 단지 프록시 기능만을 수행 할 뿐인데요, PHP-FPM이라는 PHP fast process manege 프로그램을 통해서 PHP를 해석하고 받은 결과를 클라이언트에게 서비스하는 방식으로 구현해야 합니다.

먼저 nginx 기본설정을 수정합니다.

```bash
USERID="jang"
BASE="/home/${USERID}"
CONF_NGINX="${BASE}/conf/nginx"
EXPIRES="7d"
mkdir -p $CONF_NGINX/conf.d
echo "user ${USERID};
pid /run/nginx.pid;
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    multi_accept on;
    worker_connections 65535;
}

http {
    charset utf-8;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    server_tokens off;
    log_not_found off;
    types_hash_max_size 2048;
    client_max_body_size 32M;

    # MIME
    include mime.types;
    default_type application/octet-stream;

    # logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;

    # load configs
    include ${CONF_NGINX}/conf.d/*.conf;
}
" > /etc/nginx/nginx.conf

echo "# security headers
add_header X-XSS-Protection          \"1; mode=block\" always;
add_header X-Content-Type-Options    \"nosniff\" always;
add_header Referrer-Policy           \"no-referrer-when-downgrade\" always;
add_header Content-Security-Policy   \"default-src 'self' http: https: data: blob: 'unsafe-inline'; frame-ancestors 'self';\" always;
add_header Permissions-Policy        \"interest-cohort=()\" always;
add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;
" > $CONF_NGINX/security.conf

echo "# favicon.ico
location = /favicon.ico {
    log_not_found off;
    access_log off;
}

# robots.txt
location = /robots.txt {
    log_not_found off;
    access_log off;
}

# assets, media
location ~* \.(?:css(\.map)?|js(\.map)?|jpe?g|png|gif|ico|cur|heic|webp|tiff?|mp3|m4a|aac|ogg|midi?|wav|mp4|mov|webm|mpe?g|avi|ogv|flv|wmv)$ {
    expires ${EXPIRES};
    access_log off;
}

# svg, fonts
location ~* \.(?:svgz?|ttf|ttc|otf|eot|woff2?)$ {
    add_header Access-Control-Allow-Origin \"*\";
    expires ${EXPIRES};
    access_log off;
}

# gzip
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;
" > $CONF_NGINX/general.conf

echo "# 404
try_files \$fastcgi_script_name =404;

# default fastcgi_params
include fastcgi_params;

# fastcgi settings
fastcgi_pass        unix:/var/run/php/${USERID}.sock;
fastcgi_index       index.php;
fastcgi_buffers     8 16k;
fastcgi_buffer_size 32k;

# fastcgi params
fastcgi_param DOCUMENT_ROOT   \$realpath_root;
fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
fastcgi_param PHP_ADMIN_VALUE \"open_basedir=\$base/:/usr/lib/php/:/tmp/\";
" > $CONF_NGINX/php_fastcgi.conf

echo "proxy_http_version 1.1;
proxy_cache_bypass \$http_upgrade;

proxy_set_header Upgrade           \$http_upgrade;
proxy_set_header Connection        \"upgrade\";
proxy_set_header Host              \$host;
proxy_set_header X-Real-IP         \$remote_addr;
proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto \$scheme;
proxy_set_header X-Forwarded-Host  \$host;
proxy_set_header X-Forwarded-Port  \$server_port;
" > $CONF_NGINX/proxy.conf

echo "server {
    listen 80;
    listen [::]:80;

    server_name _;
    set \$base ${BASE};
    root \$base/default;

    # security
    include ${CONF_NGINX}/security.conf;

    # logging
    access_log /var/log/nginx/default.access.log;
    error_log /var/log/nginx/default.error.log warn;

    # index.php
    index index.php;

    # index.php fallback
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    # handle .php
    location ~ \.php$ {
        include ${CONF_NGINX}/php_fastcgi.conf;
    }

    include ${CONF_NGINX}/general.conf;
}
" > $CONF_NGINX/conf.d/default.conf
chown -R $USERID:$USERID /home/$USERID/conf
service nginx restart

mkdir -p $BASE/default
echo "<?php phpinfo(-1);
" > $BASE/default/index.php
chown -R $USERID:$USERID ${BASE}/default
```

웹 브라우저로 서버 아이피나 도메인을 통해 접속을 시도해봅시다 php정보가 나옵니다.

## 8. 사용자별 계정 추가 및 설정

도메인에 따라서 여러개의 사이트를 운영하는 법을 알려드립니다.

### 사용자 php 설정

이제 공통의 php.ini 설정이 아닌 사용자별 PHP를 설정해줍니다.

```bash
USERID="jang"
TIMEZONE="Asia/Seoul"
PHPVERSION="8.0"
echo "[${USERID}]
user = ${USERID}
group = ${USERID}

listen = /run/php/${USERID}.sock
listen.owner = ${USERID}
listen.group = www-data

pm = dynamic
pm.max_children = 9
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 4
pm.max_requests = 200

php_admin_value[date.timezone] = ${TIMEZONE}
php_admin_value[realpath_cache_size] = 64k
php_admin_value[expose_php] = Off

php_admin_value[opcache.revalidate_freq] = 1 ;0:개발, 1:라이브수정, 2:최적성능
php_admin_value[opcache.validate_timestamps] = 1
php_admin_value[opcache.interned_strings_buffer] = 16

php_admin_value[max_execution_time] = 6000
php_admin_value[max_input_time] = 6000
php_admin_value[post_max_size] = 1024M
php_admin_value[upload_max_filesize] = 1024M

php_admin_value[session.save_handler] = 'redis'
php_admin_value[session.save_path] = 'tcp://127.0.0.1:6379'
" > /etc/php/$PHPVERSION/fpm/pool.d/$USERID.conf
service php$PHPVERSION-fpm restart
```

#### 사용자 Nginx 설정
```bash
USERID="jang"
BASE="/home/${USERID}"
DOMAIN="nginx-example.com"
CONF_NGINX="${BASE}/conf/nginx"
echo "server {
    listen 80;
    listen [::]:80;

    server_name ${DOMAIN};
    set \$base ${BASE}/${DOMAIN};
    root \$base/public;

    # security
    include ${CONF_NGINX}/security.conf;

    # logging
    access_log /var/log/nginx/${DOMAIN}.access.log;
    error_log  /var/log/nginx/${DOMAIN}.error.log warn;

    # index.php
    index index.php;

    # index.php fallback
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    # handle .php
    location ~ \.php$ {
        include ${CONF_NGINX}/php_fastcgi.conf;
    }

    include ${CONF_NGINX}/general.conf;
}
" > $CONF_NGINX/conf.d/$DOMAIN.conf
service nginx restart
```

### 사용자 데이터베이스 생성

DATABASE root 패스워드를 입력해야합니다.

```bash
DBROOTPASS="1234"
USERID="jang"
USERPW="1234"
DBNAME="test"
mysql -uroot -p$DBROOTPASS -e "CREATE DATABASE ${DBNAME}
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;"
mysql -uroot -p$DBROOTPASS -e "CREATE USER '${USERID}'@'%' IDENTIFIED BY '${USERPW}'"
mysql -uroot -p$DBROOTPASS -e "GRANT USAGE ON *.* TO '${USERID}'@'%' REQUIRE NONE WITH MAX_QUERIES_PER_HOUR 0 MAX_CONNECTIONS_PER_HOUR 0 MAX_UPDATES_PER_HOUR 0 MAX_USER_CONNECTIONS 0"
mysql -uroot -p$DBROOTPASS -e "GRANT ALL PRIVILEGES ON ${DBNAME}.* TO '${USERID}'@'%'"
```

## iptables 활성화 및 포트 허용
```bash
apt-get install iptables-persistent

// 3306 포트 인바운드 아웃바운드 허용
iptables -I INPUT -p tcp --dport 3306 -j ACCEPT

// 재부팅시 추가한 내역이 사라지므로 저장해둔다.
netfilter-persistent save
netfilter-persistent reload
```

## 어플리케이션 설치

```bash
su -l jang
cd ~
git clone git@github.com:Roy-Jang/example-nginx.git nginx-example.com
cd ~/nginx-example.com
composer install
```

## 저널 로그 2일치
```bash
sudo journalctl --vacuum-time=2days
```

## alias 셋팅 (jang)

우분투 단축기 설정입니다.

```bash
vim ~/.bashrc

// 복사 붙여넣기
alias w='cd /home/jang'
alias s='source ~/.bashrc'
alias config='vim ~/.bashrc'
alias r='sudo service nginx stop && sudo service nginx start && sudo service php8.0-fpm stop && sudo service php8.0-fpm start && sudo service mariadb stop && sudo service mariadb start'
alias jangphpconf='vim /home/jang/conf/php/jang.conf'
alias jangngnix='cd /home/jang/conf/nginx'
alias jangconf='cd /home/jang/conf/nginx/conf.d'
alias vimhost='sudo vim /mnt/c/Windows/System32/drivers/etc/hosts'
alias c='code .'
alias l='ls -al'
alias nrestart='sudo service nginx stop && sudo service nginx start'
alias prestart='sudo service php7.4-fpm stop && sudo service php7.4-fpm start'
alias mrestart='sudo service mariadb stop && sudo service mariadb start'
// 복사 붙여넣기

source ~/.bashrc
```