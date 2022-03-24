#! /bin/bash

# Immediately fail if anything goes wrong.
set -e

# print commands and their expanded arguments
set -x

# These environment variables are set by Vagrant
set -o allexport
source /vagrant/$1
set +o allexport

apt-get update

apt-get install -y build-essential \
  python3-dev \
  python3-pip \
  supervisor \
  nginx \
  pkg-config \
  libcairo2-dev

pip3 install -r /vagrant/auth_demo/requirements.txt

# setup some static environment variables
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

# Create the dir from which nginx will eventually serve static files
mkdir -p /www
mkdir -p /var/log/demo
chown vagrant:vagrant /var/log/demo

# # Apply database migrations, collect the static files to server, and create
# # a superuser based on the environment variables passed to the container.
# remove any sqlite dbs, if they exist:
rm -f /vagrant/auth_demo/db.sqlite3
/usr/bin/python3 /vagrant/auth_demo/manage.py migrate
/usr/bin/python3 /vagrant/auth_demo/manage.py createsuperuser --noinput

# # The collectstatic command gets all the static files 
# # and puts them at /vagrant/auth_demo/static.
# # We them copy the contents to /www/static so nginx can serve:
/usr/bin/python3 /vagrant/auth_demo/manage.py collectstatic --noinput
cp -r /vagrant/auth_demo/static /www/static

cp /vagrant/auth_demo/gunicorn.conf /etc/supervisor/conf.d/
supervisorctl reread
supervisorctl update
supervisorctl start gunicorn

# # Restart nginx so it loads the new config:
rm /etc/nginx/sites-enabled/default
cp /vagrant/auth_demo/demo_nginx.conf /etc/nginx/sites-enabled/
service nginx restart
