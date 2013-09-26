#!/bin/bash

apt-get -y install libxml2-dev libxslt-dev
pip install html5lib
pip install lxml
pip install requests

if [ ! -d /usr/local/sslassert ]; then
    mkdir /usr/local/sslassert
fi

cp -f -r * /usr/local/sslassert/

if [ ! -d /etc/service/sslassert/ ]; then
    mkdir /etc/service/sslassert/
fi

cat >/etc/service/sslassert/run <<EOF
#!/bin/sh
/usr/bin/sv start nginx || exit 1
cd /usr/local/sslassert
exec ./server.py \
    --log_to_stderr \
    --logging=debug \
    2>&1
EOF
chmod a+x /etc/service/sslassert/run

if [ ! -d /var/log/sslassert ]; then
    mkdir /var/log/sslassert
fi

if [ ! -d /etc/service/sslassert/log ]; then
    mkdir /etc/service/sslassert/log
fi

cat >/etc/service/sslassert/log/run <<\EOT
#!/bin/sh
exec /usr/bin/svlogd -tt /var/log/sslassert

EOT
chmod a+x /etc/service/sslassert/log/run

