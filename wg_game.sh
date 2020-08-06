#!/bin/bash

###notice###
#wireguard + udpspeeder + udp2raw game accelerator program. 
#speeder fec mode: f2:4,traffic usage increased by 2 times.
#udp2raw config: MTU is recommended to be less than 1200

function rand(){
    min=$1
    max=$(($2-$min+1))
    num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
    echo $(($num%$max+$min))
}

function randpasswd(){
    mpasswd=`cat /dev/urandom | head -1 | md5sum | head -c 4`
    echo $mpasswd  
}

function release_check(){
    source /etc/os-release
    RELEASE=$ID
    VERSION=$VERSION_ID
}

function centos_selinux(){
    if [ -f "/etc/selinux/config" ]; then
        SELINUX_STATUS=`grep SELINUX= /etc/selinux/config | grep -v "#"`
        if [ "$SELINUX_STATUS" != "SELINUX=disabled" ]; then
            echo "SELinux is working,write wireguard & udp2raw ports to rules"
            yum install -y policycoreutils-python >/dev/null 2>&1
            semanage port -a -t http_port_t -p udp $WIREGUARD_PORT
            semanage port -a -t http_port_t -p udp $UDP2RAW_PORT
            semanage port -a -t http_port_t -p tcp $UDP2RAW_PORT
            fi
    fi
}

function centos_firewalld(){
    FIREWALLD_STATUS=`systemctl status firewalld | grep "Active: active"`
    if [ -n "$FIREWALLD_STATUS" ]; then
        echo "Firewalld is working,write wireguard & udp2raw ports to rules"
        firewall-cmd --zone=public --add-port=$WIREGUARD_PORT/udp --permanent
        firewall-cmd --zone=public --add-masquerade --permanent
        firewall-cmd --zone=public --add-port=$UDP2RAW_PORT/udp --permanent
        firewall-cmd --zone=public --add-port=$UDP2RAW_PORT/tcp --permanent
        firewall-cmd --reload
    fi
}

function ufw_check(){
    UFW_STATUS=`systemctl status ufw | grep "Active: active"`
    if [ -n "$UFW_STATUS" ]; then
        ufw allow $WIREGUARD_PORT/udp
        ufw allow $UDP2RAW_PORT/udp
        ufw allow $UDP2RAW_PORT/tcp
    fi
}

function wireguard_install(){
    release_check
    WIREGUARD_PORT=`rand 10000 60000`
    UDP2RAW_PORT=`rand 10000 60000`
    UDP_PASSWORD=`randpasswd`
    SERVER_IP=`curl ipv4.icanhazip.com`
    ETH=`ls /sys/class/net| grep ^e | head -n 1`
    if [ "$RELEASE" == "centos" ] && [ "$VERSION" == "7" ]; then
        centos_selinux
        centos_firewalld
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
        yum install -y "kernel-devel-uname-r == $(uname -r)" dkms wget
        curl -o /etc/yum.repos.d/jdoss-wireguard-epel-7.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
        yum install -y wireguard-dkms wireguard-tools qrencode iptables-services
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        sysctl -p
    elif [ "$RELEASE" == "centos" ] && [ "$VERSION" == "8" ]; then
        centos_selinux
        centos_firewalld
        yum install -y epel-release
        yum install -y "kernel-devel-uname-r == $(uname -r)" dkms wget
        yum config-manager --set-enabled PowerTools
        yum copr enable -y jdoss/wireguard
        yum install -y wireguard-dkms wireguard-tools qrencode
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        sysctl -p
    elif [ "$RELEASE" == "ubuntu" ]  && [ "$VERSION" == "19.04" ]; then
        echo "==================="
        echo "ubuntu19.04 does not support."
        echo "==================="
    elif [ "$RELEASE" == "ubuntu" ]  && [ "$VERSION" == "19.10" ]; then 
        echo "==================="
        echo "ubuntu19.10 does not support."
        echo "==================="
    elif [ "$RELEASE" == "ubuntu" ]  && [ "$VERSION" == "16.04" ]; then
        ufw_check
        apt-get -y update 
        add-apt-repository -y ppa:wireguard/wireguard
        apt-get update
        apt-get install -y wireguard qrencode wget
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        sysctl -p
    elif [ "$RELEASE" == "ubuntu" ] && [ "$VERSION" == "18.04" ]; then
        ufw_check
        apt-get -y update 
        apt-get install -y software-properties-common wget
        apt-get install -y openresolv
        add-apt-repository -y ppa:wireguard/wireguard
        apt-get -y update
        apt-get install -y wireguard qrencode 
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        sysctl -p
    elif [ "$RELEASE" == "debian" ]; then
        ufw_check
        echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
        printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
        apt update
        apt install -y wireguard qrencode wget
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        sysctl -p
    else
        echo "Your current system does not support."
    fi
}

function wireguard_config(){
    mkdir /etc/wireguard /etc/wireguard/client /etc/wireguard/udp
    cd /etc/wireguard/udp
    wget https://github.com/duckga/wireguard/raw/master/speederv2
    wget https://github.com/duckga/wireguard/raw/master/udp2raw
cat > /etc/wireguard/udp/run.sh <<-EOF
#!/bin/sh
while true
do
$@
sleep 1
done
EOF

cat > /etc/wireguard/udp/start.sh <<-EOF
#!/bin/bash
nohup /etc/wireguard/udp/speederv2 -s -l127.0.0.1:23333 -r127.0.0.1:$WIREGUARD_PORT -f2:4 --mode 0 --timeout 0 >speeder.log 2>&1 & 
nohup /etc/wireguard/udp/udp2raw -s -l0.0.0.0:$UDP2RAW_PORT -r 127.0.0.1:23333  --raw-mode faketcp -k $UDP_PASSWORD >udp2raw.log 2>&1 &
EOF

cat > /etc/wireguard/udp/stop.sh <<-EOF
#!/bin/bash
kill -9 \`ps -ef | grep "speederv2" | grep -v grep | awk '{print $2}'\`
kill -9 \`ps -ef | grep "udp2raw" | grep -v grep | awk '{print $2}'\`
EOF

    chmod +x speederv2 udp2raw run.sh start.sh stop.sh

cat > /etc/systemd/system/udp.service <<-EOF
[Unit]  
Description=udp 
After=network.target  
   
[Service]  
Type=forking  
ExecStart=/etc/wireguard/udp/start.sh
ExecStop=/etc/wireguard/udp/stop.sh

   
[Install]  
WantedBy=multi-user.target
EOF
    chmod +x /etc/systemd/system/udp.service
    systemctl start udp.service
    systemctl enable udp.service
    cd /etc/wireguard
    wg genkey | tee sprivatekey | wg pubkey > spublickey
    wg genkey | tee cprivatekey | wg pubkey > cpublickey
    S1=`cat sprivatekey`
    S2=`cat spublickey`
    C1=`cat cprivatekey`
    C2=`cat cpublickey`
    chmod 777 -R /etc/wireguard

cat > /etc/wireguard/wg0.conf <<-EOF
[Interface]
PrivateKey = $S1
Address = 10.77.0.1/24 
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $ETH -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $ETH -j MASQUERADE
ListenPort = $WIREGUARD_PORT
DNS = 8.8.8.8
MTU = 1200
[Peer]
PublicKey = $C2
AllowedIPs = 10.77.0.2/32
EOF

cat > /etc/wireguard/client/default.conf <<-EOF
[Interface]
PrivateKey = $C1
PostUp = mshta vbscript:CreateObject("WScript.Shell").Run("cmd /c route add $SERVER_IP mask 255.255.255.255 192.168.1.1 METRIC 20 & start /b c:/udp/speederv2.exe -c -l127.0.0.1:2090 -r127.0.0.1:2091 -f2:4 --mode 0 --timeout 0 & start /b c:/udp/udp2raw.exe -c -r$SERVER_IP:$UDP2RAW_PORT -l127.0.0.1:2091 --raw-mode faketcp -k $UDP_PASSWORD",0)(window.close)
PostDown = route delete $SERVER_IP && taskkill /im udp2raw.exe /f && taskkill /im speederv2.exe /f
Address = 10.77.0.2/24 
DNS = 8.8.8.8
MTU = 1420
[Peer]
PublicKey = $S2
Endpoint = 127.0.0.1:2090
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepalive = 25
EOF
    wg-quick up wg0
    systemctl enable wg-quick@wg0
}

function user_add(){
    read -p "Input a new name：" newname
    cd /etc/wireguard/client
    if [ ! -f "/etc/wireguard/client/$newname.conf" ]; then
        cp default.conf $newname.conf
        wg genkey | tee temprikey | wg pubkey > tempubkey
        ipnum=`grep Allowed /etc/wireguard/wg0.conf | tail -1 | awk -F '[ ./]' '{print $6}'`
        newnum=$((10#${ipnum}+1))
        sed -i 's%^PrivateKey.*$%'"PrivateKey = $(cat temprikey)"'%' $newname.conf
        sed -i 's%^Address.*$%'"Address = 10.77.0.$newnum\/24"'%' $newname.conf
        cat >> /etc/wireguard/wg0.conf <<-EOF
[Peer]
PublicKey = `cat tempubkey`
AllowedIPs = 10.77.0.$newnum/32
EOF
        wg set wg0 peer `cat tempubkey` allowed-ips 10.77.0.$newnum/32
        echo "Success, file path: /etc/wireguard/client/$newname.conf"
        rm -f temprikey tempubkey
    else
        echo "$newname already exist"
    fi

}

function wireguard_remove(){
    release_check
    if [ -d "/etc/wireguard" ]; then
        wg-quick down wg0
        if [ "$RELEASE" == "centos" ]; then
            yum remove -y wireguard-dkms wireguard-tools
            rm -rf /etc/wireguard/
            echo "remove done"
        elif [ "$RELEASE" == "ubuntu" ]; then
            apt-get remove -y wireguard
            rm -rf /etc/wireguard/
            echo "remove done"
        elif [ "$RELEASE" == "debian" ]; then
            apt remove -y wireguard
            rm -rf /etc/wireguard/
            echo "remove done"
        else
            echo "remove faild"
        fi
    else
        echo "wireguard not installed"
    fi
}

function menu_show(){
    clear
    echo "####################################"
    echo "# WireGuard + udpspeeder + udp2raw #"
    echo "# For  Centos7+/Ubuntu16+/Debian9+ #"
    echo "#             Author A             #"
    echo "####################################"
    echo "1. Install wireguard"
    echo "2. Remove wireguard"
    echo "3. Add user"
    echo "0. Exit"
    echo
    read -p "Please enter a number:" num
    case "$num" in
    1)
    wireguard_install
    wireguard_config
    ;;
    2)
    wireguard_remove
    ;;
    3)
    user_add
    ;;
    0)
    exit 1
    ;;
    *)
    clear
    echo "Please enter a correct number!"
    sleep 1s
    start_menu
    ;;
    esac
}

menu_show
