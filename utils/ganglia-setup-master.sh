apt-get install -y apache2
apt-get install -y ganglia-monitor
apt-get install -y rrdtool
apt-get install -y gmetad
apt-get install -y ganglia-frontend

cp /etc/ganglia-webfrontend/apache.conf /etc/apache2/sites-enabled/ganglia.conf

systemctl enable ganglia-monitor 
systemctl start ganglia-monitor 
systemctl enable gmetad 
systemctl start gmetad 
systemctl restart apache2
