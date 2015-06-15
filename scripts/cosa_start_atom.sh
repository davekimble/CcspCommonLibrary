#######################################################################
#   Copyright [2014] [Cisco Systems, Inc.]
# 
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################

#if [ -e /mnt/sysdata0/switch ]; then
#   cd /mnt/appdata0/cc
#   ./cosa_start.sh
#   exit 0
#fi

#if [ "x"$1 = "x" ];then
#    sleep 40
#fi

killall CcspWifiSsp

# have IP address for dbus config generated
vconfig add eth0 500
ifconfig eth0.500 192.168.101.3

export LD_LIBRARY_PATH=$PWD:.:$PWD/lib:/lib:/usr/lib:$LD_LIBRARY_PATH

#mkdir -p /nvram/ccsp
#cp ccsp_msg.cfg /nvram/ccsp
cp ccsp_msg.cfg /tmp

if [ "x"$1 = "x" ];then
    sleep 10
fi

# have IP address for dbus config generated
#./DbusCfg

Subsys="eRT."

echo "Elected subsystem is $Subsys"

sleep 1

if [ -e ./wifi ]; then
	cd wifi 
	if [ "x"$Subsys = "x" ];then
    	./CcspWifiSsp &
	else
    	echo "./CcspWifiSsp -subsys $Subsys &"
    	./CcspWifiSsp -subsys $Subsys &
	fi
fi

