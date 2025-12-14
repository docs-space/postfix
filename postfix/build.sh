#!/bin/sh
VERSION=$1
BUILD_DIRECTORY=/opt/r7-mailserver/mtaserver
PACK_DIRECTORY=$2/Pack/opt/r7-mailserver

sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    autoconf \
    automake \
    libtool \
    pkg-config \
    curl \
    wget \
    tar \
    gzip \
    bzip2 \
    xz-utils

# Общие зависимости Postfix
sudo apt-get install -y \
    libssl-dev \
    libsasl2-dev \
    libpcre3-dev \
    libdb-dev \
    libldap2-dev \
    libpq-dev \
    libmysqlclient-dev \
    libsqlite3-dev \
    libcdb-dev \
    liblzma-dev \
    libz-dev \
    libbz2-dev \
    liblz4-dev \
    libzstd-dev \
    libicu-dev \
    libxml2-dev \
    libpam0g-dev \
    libcap-dev \
    libaudit-dev \
    libselinux1-dev \
    libwrap0-dev \
    libkrb5-dev \
    libgssapi-krb5-2 \
    libgssrpc4

# Альтернативно для минимальной сборки
sudo apt-get install -y \
    gcc make libssl-dev libsasl2-dev libpcre3-dev libdb-dev

sudo rm -rf ${BUILD_DIRECTORY}
sudo mkdir -p ${BUILD_DIRECTORY}/usr/sbin \
    ${BUILD_DIRECTORY}/etc/postfix \
    ${BUILD_DIRECTORY}/usr/libexec/postfix \
    ${BUILD_DIRECTORY}/var/lib/postfix \
    ${BUILD_DIRECTORY}/usr/bin \
    ${BUILD_DIRECTORY}/usr/share/doc/postfix/html \
    ${BUILD_DIRECTORY}/usr/share/man \
    ${BUILD_DIRECTORY}/var/spool/postfix \
    ${BUILD_DIRECTORY}/usr/share/doc/postfix \
    ${BUILD_DIRECTORY}/etc/postfix/samples
sudo touch $BUILD_DIRECTORY/etc/postfix/master.cf
sudo touch $BUILD_DIRECTORY/etc/postfix/main.cf

sudo adduser --system --group --home $BUILD_DIRECTORY --gecos "Postfix mail server" \
        --no-create-home --disabled-password --quiet postfix || true
sudo addgroup --quiet postdrop || true

sudo make makefiles \
    shared=yes \
    dynamicmaps=yes \
    shlib_directory=${BUILD_DIRECTORY}/lib \
    meta_directory=${BUILD_DIRECTORY}/meta \
    AUXLIBS_PGSQL="-L/usr/local/lib -lpq" \
    CCARGS="-DFD_SETSIZE=2048 \
            -DDEF_COMMAND_DIR=\\\"${BUILD_DIRECTORY}/usr/sbin\\\" \
            -DDEF_CONFIG_DIR=\\\"${BUILD_DIRECTORY}/etc/postfix\\\" \
            -DDEF_DAEMON_DIR=\\\"${BUILD_DIRECTORY}/usr/libexec/postfix\\\" \
            -DDEF_DATA_DIR=\\\"${BUILD_DIRECTORY}/var/lib/postfix\\\" \
            -DDEF_MAILQ_PATH=\\\"${BUILD_DIRECTORY}/usr/bin/mailq\\\" \
            -DDEF_HTML_DIR=\\\"${BUILD_DIRECTORY}/usr/share/doc/postfix/html\\\" \
            -DDEF_MANPAGE_DIR=\\\"${BUILD_DIRECTORY}/usr/share/man\\\" \
            -DDEF_NEWALIAS_PATH=\\\"${BUILD_DIRECTORY}/usr/bin/newaliases\\\" \
            -DDEF_QUEUE_DIR=\\\"${BUILD_DIRECTORY}/var/spool/postfix\\\" \
            -DDEF_README_DIR=\\\"${BUILD_DIRECTORY}/usr/share/doc/postfix\\\" \
            -DDEF_SENDMAIL_PATH=\\\"${BUILD_DIRECTORY}/usr/sbin/sendmail\\\" \
            -DDEF_SAMPLE_DIR=\\\"${BUILD_DIRECTORY}/etc/postfix/samples\\\" \
            -DHAS_PGSQL -I/usr/include/postgresql \
            -DUSE_SASL_AUTH \
            -DDEF_SERVER_SASL_TYPE=\\\"dovecot\\\" \
            -DUSE_TLS \
            -DHAS_PCRE \
            -DHAS_UNBOUND \
            -DHAS_FCNTL_LOCK \
            -DHAS_FLOCK_LOCK \
            -DDEF_MAILBOX_LOCK='fcntl' \
            -DINTERNAL_LOCK='fcntl' \
            -DUSE_STATFS \
            -DSOCKADDR_SIZE=16" \
    AUXLIBS="-lssl -lcrypto \
             -lsasl2 \
             -lpq \
             -lpcre \
             -lunbound \
             -lz -llz4 -lzstd -lbz2 -llzma"


sudo make
sudo make install POSTFIX_INSTALL_OPTS="-non-interactive"

sudo cp -r $BUILD_DIRECTORY $PACK_DIRECTORY/
sudo rm -rf $BUILD_DIRECTORY
sudo cp -r $2/config/* $PACK_DIRECTORY/mtaserver/etc/postfix