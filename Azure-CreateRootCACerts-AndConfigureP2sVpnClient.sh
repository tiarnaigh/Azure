# The below works on a ubuntu 18.04 VM running Linux strongSwan U5.6.2/K4.15.0-163-generic. I have not tested with newer ubuntu20/22 onwards....
# 
# Install below addtional packages before running the script:
# root@ubuntu18-node:~/azureVpn# apt install strongswan strongswan-pki libstrongswan-extra-plugins curl libxml2-utils cifs-utils libcharon-extra-plugins
#
# Sample run:
# root@ubuntu18-node:~/azureVpn# az login --tenant 463c930a-d310-462b-********
# root@ubuntu18-node:~/azureVpn# az account set --subscription="nprd-mgmt"
# root@ubuntu18-node:~/azureVpn# az resource list -o table | grep virtualNetworkGateways
# nprd-eastus-mgmt-vnet-gw                                                                      nprd-eastus-mgmt-rg                                 eastus      Microsoft.Network/virtualNetworkGateways
# root@dubuntu18-node:~/azureVpn#
#
# Kick off script to create the P2S Root CA bundle (Gets pushed/uploaded to VPN-GW)
# Script also create client key/cert, signed from root CA and these are used to communicate with VPN-GW
#
# root@ubuntu18-node:~/azureVpn# sh Azure-CreateRootCACerts-AndConfigureP2sVpnClient.sh
# % Total % Received % Xferd Average Speed Time Time Time Current
# Dload Upload Total Spent Left Speed
# 100 296k 100 296k 0 0 451k 0 --:--:-- --:--:-- --:--:-- 451k
# Archive: vpnClient.zip
# warning: vpnClient.zip appears to use backslashes as path separators
# inflating: Generic/VpnSettings.xml
# inflating: Generic/VpnServerRoot.cer
# inflating: OpenVPN/vpnconfig.ovpn
# inflating: AzureVPN/azurevpnconfig.xml
# inflating: WindowsAmd64/VpnClientSetupAmd64.exe
# inflating: WindowsX86/VpnClientSetupX86.exe
# Stopping strongSwan IPsec failed: starter is not running
# Starting strongSwan 5.6.2 IPsec [starter]...
# /etc/ipsec.conf:29: syntax error, unexpected STRING [-e]
# invalid config file '/etc/ipsec.conf'
# unable to start strongSwan -- fatal errors in config
# root@dvops4lab0:~/azureVpn#
#
# Note: The /etc/ipsec.conf comes out a little "screwy" from above (Need to fix up the script to remove the "-e" chars... 
# End state file should look like the below 
# root@ubuntu18-node:~/azureVpn# cat /etc/ipsec.conf
# conn nprd-eastus-mgmt-vnet
#        keyexchange=ikev2
#        type=tunnel
#        leftfirewall=yes
#        left=%any
#        leftauth=eap-tls
#        leftid=%client
#        right=azuregateway-2cde0077-c061-4ac1-a0a3-b9e4293b3d62-def533******.vpn.azure.com
#        rightid=%azuregateway-2cde0077-c061-4ac1-a0a3-b9e4293b3d62-def533******.vpn.azure.com
#        rightsubnet=10.1.0.0/16,10.2.0.0/21,10.3.0.0/16,10.4.0.0/16,10.5.0.0/16,10.25.1.0/24,10.16.0.0/16,10.27.0.0/16,10.28.0.0/16
#        leftsourceip=%config
#        auto=add
#        dpddelay=60s
#        dpdtimeout=300s
#        dpdaction=restart
#        auto=start


# root@ubuntu18-node:~/azureVpn# cat Azure-CreateRootCACerts-AndConfigureP2sVpnClient.sh
installDir="/etc/"
rootCertName="P2SRootCert_202307"
username="client"
password="pass123!"
resourceGroupName="nprd-eastus-mgmt-rg"
virtualNetworkName="nprd-eastus-mgmt-vnet"
vpnName="nprd-eastus-mgmt-vnet-gw"


#mkdir temp
#cd temp

sudo ipsec pki --gen --outform pem > rootKey.pem
sudo ipsec pki --self --in rootKey.pem --dn "CN=$rootCertName" --ca --outform pem > rootCert.pem

rootCertificate=$(openssl x509 -in rootCert.pem -outform der | base64 -w0 ; echo)

sudo ipsec pki --gen --size 4096 --outform pem > "clientKey.pem"
sudo ipsec pki --pub --in "clientKey.pem" | \
sudo ipsec pki \
--issue \
--cacert rootCert.pem \
--cakey rootKey.pem \
--dn "CN=$username" \
--san $username \
--flag clientAuth \
--outform pem > "clientCert.pem"

openssl pkcs12 -in "clientCert.pem" -inkey "clientKey.pem" -certfile rootCert.pem -export -out "client.p12" -password "pass:$password"


# Add new Root certificate to VPN GW side (Need to be authenticated via az cli in advance and with appropriate permissions in subscription & RG)
az network vnet-gateway root-cert create \
--resource-group $resourceGroupName \
--gateway-name $vpnName \
--name $rootCertName \
--public-cert-data $rootCertificate \
--output none


vpnClient=$(az network vnet-gateway vpn-client generate \
--resource-group $resourceGroupName \
--name $vpnName \
--authentication-method EAPTLS | tr -d '"')

curl $vpnClient --output vpnClient.zip
unzip vpnClient.zip

vpnServer=$(xmllint --xpath "string(/VpnProfile/VpnServer)" Generic/VpnSettings.xml)
vpnType=$(xmllint --xpath "string(/VpnProfile/VpnType)" Generic/VpnSettings.xml | tr '[:upper:]' '[:lower:]')
routes=$(xmllint --xpath "string(/VpnProfile/Routes)" Generic/VpnSettings.xml)

sudo cp "${installDir}ipsec.conf" "${installDir}ipsec.conf.backup"
sudo cp "Generic/VpnServerRoot.cer_0" "${installDir}ipsec.d/cacerts"
sudo cp "${username}.p12" "${installDir}ipsec.d/private"



echo -e "\nconn $virtualNetworkName" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\tkeyexchange=$vpnType" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\ttype=tunnel" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\tleftfirewall=yes" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\tleft=%any" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\tleftauth=eap-tls" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\tleftid=%client" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\tright=$vpnServer" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\trightid=%$vpnServer" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\trightsubnet=$routes" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\tleftsourceip=%config" | sudo tee -a "${installDir}ipsec.conf" > /dev/null
echo -e "\tauto=add" | sudo tee -a "${installDir}ipsec.conf" > /dev/null

echo ": P12 client.p12 '$password'" | sudo tee -a "${installDir}ipsec.secrets" > /dev/null

sudo ipsec restart
sudo ipsec up $virtualNetworkName
root@ubuntu18-node:~/azureVpn#

# Validate
# root@ubuntu18-node:~/azureVpn# /usr/sbin/service ipsec restart && /usr/sbin/ipsec up nprd-eastus-mgmt-vnet
# establishing CHILD_SA nprd-eastus-mgmt-vnet{2}
# generating CREATE_CHILD_SA request 11 [ SA No TSi TSr ]
# sending packet: from 10.157.192.66[4500] to 52.186.165.104[4500] (369 bytes)
# received packet: from 52.186.165.104[4500] to 10.157.192.66[4500] (696 bytes)
# parsed CREATE_CHILD_SA response 11 [ SA No TSi TSr ]
# CHILD_SA nprd-eastus-mgmt-vnet{2} established with SPIs c1985a10_i 62d6d17e_o and TS 172.16.0.2/32 === 10.1.7.0/24 10.1.40.0/24 10.2.0.0/21 10.3.1.0/24 10.3.3.0/24 10.3.6.0/24 10.3.10.0/23 10.5.8.0/24 10.5.17.0/24 10.5.18.0/24 10.5.19.0/24 10.16.0.0/23 10.27.0.0/16 10.28.0.0/16
# connection 'nprd-eastus-mgmt-vnet' established successfully
# root@ubuntu18-node:~/azureVpn#

# root@ubuntu18-node:~/azureVpn# ping 10.2.0.68
# PING 10.2.0.68 (10.2.0.68) 56(84) bytes of data.
# 64 bytes from 10.2.0.68: icmp_seq=1 ttl=64 time=25.3 ms
# 64 bytes from 10.2.0.68: icmp_seq=2 ttl=64 time=25.0 ms
# 64 bytes from 10.2.0.68: icmp_seq=3 ttl=64 time=24.7 ms
# ^C


