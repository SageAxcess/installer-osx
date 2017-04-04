#!/bin/sh

function sedreplace {
  set -f
  key=$(echo $1 | sed -e 's/\([[\/.*]\|\]\)/\\&/g')
  val=$(echo $2 | sed -e 's/[\/&]/\\&/g')

  echo "Applying $1 = $val"

  sed -i "s/^\($key\s*=\s*\).*\$/\1$val/" $3
}

echo "Configure aegis service now"

if [ -f install-settings.ini ]; then
iface=$(awk -F "=" '/ListenInterface/ {print $2}' install-settings.ini)
agg_host=$(awk -F "=" '/AggregatorHost/ {print $2}' install-settings.ini)
agg_port=$(awk -F "=" '/AggregatorPort/ {print $2}' install-settings.ini)
agg_bind="tcp://${agg_host}:${agg_port}"
agg_key=$(awk -F "=" '/AggregatorPublicKey/ {print $2}' install-settings.ini)
agent_port=$(awk -F "=" '/AgentPort/ {print $2}' install-settings.ini)
agent_port_ssl=$(awk -F "=" '/AgentHttpsPort/ {print $2}' install-settings.ini)
updates_enabled=$(awk -F "=" '/EnableUpdates/ {print $2}' install-settings.ini)
control_enabled=$(awk -F "=" '/EnableControl/ {print $2}' install-settings.ini)
else
read -p "  Listen interface [*]: " iface
read -p "  Aggregator url [tcp://localhost:5555]: " agg_bind
read -p "  Aggregator public key [5A58...]: " agg_key
read -p "  Agent port [8111]: " agent_port
read -p "  Agent port(ssl) [8112]: " agent_port_ssl
read -p "  Updates enabled (yes/no) [no]: " updates_enabled
read -p "  Remote control enabled (yes/no) [yes]: " control_enabled
fi

if [[ -z $iface ]]; then
iface="*"
fi
if [ -z $agg_bind ]; then
agg_bind="tcp://localhost:5555"
fi
if [ -z $agg_key ]; then
agg_key="5A5832576F434D2D57367D667148464865326E3C4B74586B733C574C7A624E6355642D5239282E7200"
fi
if [ -z $agent_port ]; then
agent_port="8111"
fi
if [ -z $agent_port_ssl ]; then
agent_port="8112"
fi
if [ -z $updates_enabled ]; then
updates_enabled="false"
fi
if [ -z $control_enabled ]; then
control_enabled="true"
fi

if [[ "$updates_enabled"=="yes" || "$updates_enabled"=="on" || "$updates_enabled"=="true" || "$updates_enabled"=="1" ]]; then
updates_enabled="true"
else
updates_enabled="false"
fi

if [[ "$control_enabled"=="yes" || "$control_enabled"=="on" || "$control_enabled"=="true" || "$control_enabled"=="1" ]]; then
control_enabled="true"
else
control_enabled="false"
fi

sedreplace "listen.interface" "$iface" /usr/local/Cellar/aegis/2.4.1/conf/aegis.conf
sedreplace "zmq.server" "$agg_bind" /usr/local/Cellar/aegis/2.4.1/conf/aegis.conf
sedreplace "zmq.public_key" "$agg_key" /usr/local/Cellar/aegis/2.4.1/conf/aegis.conf
sedreplace "agent.port" "$agent_port" /usr/local/Cellar/aegis/2.4.1/conf/aegis.conf
sedreplace "agent.port.ssl" "$agent_port_ssl" /usr/local/Cellar/aegis/2.4.1/conf/aegis.conf
sedreplace "remote.control" "$control_enabled" /usr/local/Cellar/aegis/2.4.1/conf/aegis.conf
sedreplace "updates.enabled" "$updates_enabled" /usr/local/Cellar/aegis/2.4.1/conf/aegis.conf
