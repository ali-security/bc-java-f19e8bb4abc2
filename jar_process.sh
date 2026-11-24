export JAVA_HOME=/opt/java/jdk-9+181
export PATH=$JAVA_HOME/bin:$PATH

sh add_module.sh prov

sh add_module.sh prov-ext

sh add_module.sh tls

sh add_module.sh pkix

sh add_module.sh mail

sh add_module.sh pg
