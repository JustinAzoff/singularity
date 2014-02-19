#!/bin/sh
yum install -y postgresql postgresql-server perl-DBD-Pg perl-Test-Harness perl-Test-Simple
service postgresql initdb
service postgresql start


#setup db and allow vagrant user access
su - postgres -c '
createuser -DRS blackhole
createdb blackhole -O blackhole
psql blackhole < /vagrant/schema.sql
createuser -DRS vagrant
psql blackhole -c "grant all on database blackhole to vagrant"
'
