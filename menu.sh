#!/bin/bash

# Color codes
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
m="\033[0;1;36m"
y="\033[0;1;37m"
yy="\033[0;1;32m"
yl="\033[0;1;33m"
wh="\033[0m"

# Check VPS and permission
MYIP=$(wget -qO- ipinfo.io/ip);
echo "Checking VPS"
IZIN=$(curl ipinfo.io/ip | grep $MYIP)
if [ $MYIP != $MYIP ]; then
    echo -e "${NC}${RED}Permission Denied!${NC}";
    echo -e "${NC}${LIGHT}Fuck You!!"
    exit 0
fi

# Main menu
menu() {
    clear
echo "──────────────────────────────────────────────────────"
    echo -e "$y                  Mohamde tech $wh"
echo "──────────────────────────────────────────────────────"
# معلومات النظام
MYIP=$(curl -s ifconfig.me)
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || echo $MYIP)
DATE=$(date +"%Y-%m-%d")
os_info=$(lsb_release -d | cut -f2-)
uptime_info=$(uptime -p | sed 's/up //')
ram_total=$(free -m | awk '/Mem:/ {print $2}')
ram_used=$(free -m | awk '/Mem:/ {print $3}')
isp_info=$(curl -s ipinfo.io/org | cut -d' ' -f2-)
city_info=$(curl -s ipinfo.io/city)
ip_info=$(hostname -I | awk '{print $1}')
hostname_info=$(hostname)

# الحصول على NS Host (خادم الأسماء)
ns_host=$(cat /root/nsdomain)

echo -e "${yy}● System OS: ${y}$os_info${wh}"  
echo -e "${yy}● Total RAM: ${y}${ram_used} MB/${ram_total} MB${wh}"
echo -e "${yy}● Uptime: ${y}$uptime_info${wh}"
echo -e "${yy}● ISP: ${y}$isp_info${wh}"
echo -e "${yy}● City: ${y}$city_info${wh}"
echo -e "${yy}● Public IP: ${y}$MYIP${wh}"
echo -e "${yy}● Local IP: ${y}$ip_info${wh}"
echo -e "${yy}● Domain: ${y}$DOMAIN${wh}"
echo -e "${yy}● Date: ${y}$DATE${wh}"
echo -e "${yy}● NS Host: ${y}$ns_host${wh}"  
echo -e "${yy}● Owner: ${PURPLE}@a_mohamde_7${wh}"

echo "──────────────────────────────────────────────────────"
echo -e "$y-------------------------------------------------$wh"
    echo -e "$yy 1$y.  SSH & OpenVPN MENU  $wh"
    echo -e "$yy 2$y.  XRAY VMESS MENU$wh"
    echo -e "$yy 3$y.  XRAY VLESS MENU$wh"
    echo -e "$yy 4$y.  XRAY TROJAN MENU$wh"
    echo -e "$yy 5$y.  SHADOWSOCKS MENU$wh"
    echo -e "$yy 6$y.  Exit (Keluar)$wh"
    echo -e "$y-------------------------------------------------$wh"
    read -p "Select From Options [ 1 - 6 ] : " menu
    case $menu in
        1) clear; sshovpnmenu ;;
        2) clear; vmessmenu ;;
        3) clear; vlessmenu ;;
        4) clear; trojanmenu ;;
        5) clear; shadowsocksmenu ;;
        6) clear; exit ;;
        *) clear; menu ;;
    esac
}

# SSH & OpenVPN Menu
sshovpnmenu() {
    clear
    echo -e "$y                 SSH & OpenVPN $wh"
    echo -e "$y-------------------------------------------------------------$wh"
    echo -e "$yy 1$y.  Create SSH & OpenVPN Account"
    echo -e "$yy 2$y.  Generate SSH & OpenVPN Trial Account"
    echo -e "$yy 3$y.  Extending SSH & OpenVPN Account Active Life"
    echo -e "$yy 4$y.  Check User Login SSH & OpenVPN"
    echo -e "$yy 5$y.  Daftar Member SSH & OpenVPN"
    echo -e "$yy 6$y.  Delete SSH & OpenVpn Account"
    echo -e "$yy 7$y.  Delete User Expired SSH & OpenVPN"
    echo -e "$yy 8$y.  Set up Autokill SSH"
    echo -e "$yy 9$y.  Displays Users Who Do Multi Login SSH"
    echo -e "$yy 10$y. Restart All Service"
    echo -e "$yy 11$y. Menu Utama"
    echo -e "$yy 12$y. Exit"
    echo -e "$y-------------------------------------------------------------$wh"
    read -p "Select From Options [ 1 - 12 ] : " menu
    echo -e ""
    case $menu in
        1) addssh ;;
        2) trialssh ;;
        3) renewssh ;;
        4) cekssh ;;
        5) member ;;
        6) delssh ;;
        7) delexp ;;
        8) autokill ;;
        9) ceklim ;;
        10) restart ;;
        11) clear; menu ;;
        12) clear; exit ;;
        *) clear; sshovpnmenu ;;
    esac
}

# Xray Vmess Menu
vmessmenu() {
    clear
    echo -e "$y                             VMESS $wh"
    echo -e "$y-------------------------------------------------------------$wh"
    echo -e "$yy 1$y. Create Account XRAYS Vmess Websocket"
    echo -e "$yy 2$y. Delete Account XRAYS Vmess Websocket"
    echo -e "$yy 3$y. Extending Account XRAYS Vmess Active Life"
    echo -e "$yy 4$y. Check User Login XRAYS Vmess"
    echo -e "$yy 5$y. Renew Certificate XRAYS Account"
    echo -e "$yy 6$y. Menu"
    echo -e "$yy 7$y. Exit"
    echo -e "$y-------------------------------------------------------------$wh"
    read -p "Select From Options [ 1 - 7 ] : " menu
    echo -e ""
    case $menu in
        1) addvmess ;;
        2) delvmess ;;
        3) renewvmess ;;
        4) cekvmess ;;
        5) certv2ray ;;
        6) clear; menu ;;
        7) clear; exit ;;
        *) clear; vmessmenu ;;
    esac
}

# Xray Vless Menu
vlessmenu() {
    clear
    echo -e "$y                          VLESS $wh"
    echo -e "$y-------------------------------------------------------------$wh"
    echo -e "$yy 1$y. Create Account XRAYS Vless Websocket"
    echo -e "$yy 2$y. Delete Account XRAYS Vless Websocket"
    echo -e "$yy 3$y. Extending Account XRAYS Vless Active Life"
    echo -e "$yy 4$y. Check User Login XRAYS Vless"
    echo -e "$yy 5$y. Menu"
    echo -e "$yy 6$y. Exit"
    echo -e "$y-------------------------------------------------------------$wh"
    read -p "Select From Options [ 1 - 6 ] : " menu
    echo -e ""
    case $menu in
        1) addvless ;;
        2) delvless ;;
        3) renewvless ;;
        4) cekvless ;;
        5) clear; menu ;;
        6) clear; exit ;;
        *) clear; vlessmenu ;;
    esac
}

# Xray Trojan Menu
trojanmenu() {
    clear
    echo -e "$y                         TROJAN GFW $wh"
    echo -e "$y-------------------------------------------------------------$wh"
    echo -e "$yy 1$y. Create Account XRAYS Trojan"
    echo -e "$yy 2$y. Delete Account XRAYS Trojan"
    echo -e "$yy 3$y. Extending Account XRAYS Trojan Active Life"
    echo -e "$yy 4$y. Check User Login XRAYS Trojan"
    echo -e "$yy 5$y. Menu"
    echo -e "$yy 6$y. Exit"
    echo -e "$y-------------------------------------------------------------$wh"
    read -p "Select From Options [ 1 - 6 ] : " menu
    echo -e ""
    case $menu in
        1) addtrojan ;;
        2) deltrojan ;;
        3) renewtrojan ;;
        4) cektrojan ;;
        5) clear; menu ;;
        6) clear; exit ;;
        *) clear; trojanmenu ;;
    esac
}

# Shadowsocks Menu
shadowsocksmenu() {
    clear
    echo -e "$y                         SHADOWSOCKS $wh"
    echo -e "$y-------------------------------------------------------------$wh"
    echo -e "$yy 1$y. Create Account Shadowsocks"
    echo -e "$yy 2$y. Delete Account Shadowsocks"
    echo -e "$yy 3$y. Extending Account Shadowsocks Active Life"
    echo -e "$yy 4$y. Check User Login Shadowsocks"
    echo -e "$yy 5$y. Menu"
    echo -e "$yy 6$y. Exit"
    echo -e "$y-------------------------------------------------------------$wh"
    read -p "Select From Options [ 1 - 6 ] : " menu
    echo -e ""
    case $menu in
        1) addss ;;
        2) delss ;;
        3) renewss ;;
        4) cekss ;;
        5) clear; menu ;;
        6) clear; exit ;;
        *) clear; shadowsocksmenu ;;
    esac
}

# SSH Functions
addssh() {
    clear
    domain=$(cat /etc/xray/domain)
    sldomain=$(cat /root/nsdomain)
    cdndomain=$(cat /root/awscdndomain)
    slkey=$(cat /etc/slowdns/server.pub)
    clear
    read -p "Username : " Login
    read -p "Password : " Pass
    read -p "Expired (Days): " masaaktif

    IP=$(wget -qO- ipinfo.io/ip);
    ws="$(cat ~/log-install.txt | grep -w "Websocket TLS" | cut -d: -f2|sed 's/ //g')"
    ws2="$(cat ~/log-install.txt | grep -w "Websocket None TLS" | cut -d: -f2|sed 's/ //g')"
    ssl="$(cat ~/log-install.txt | grep -w "Stunnel5" | cut -d: -f2)"
    sqd="$(cat ~/log-install.txt | grep -w "Squid" | cut -d: -f2)"
    ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
    ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
    clear
    systemctl stop client-sldns
    systemctl stop server-sldns
    pkill sldns-server
    pkill sldns-client
    systemctl enable client-sldns
    systemctl enable server-sldns
    systemctl start client-sldns
    systemctl start server-sldns
    systemctl restart client-sldns
    systemctl restart server-sldns
    systemctl restart ws-tls
    systemctl restart ws-nontls
    systemctl restart ssh-ohp
    systemctl restart dropbear-ohp
    systemctl restart openvpn-ohp
    useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
    expi="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
    echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    expi=`date -d "$masaaktif days" +"%Y-%m-%d"`
    echo -e ""
    echo -e "Informasi SSH & OpenVPN"
    echo -e "=============================="
    echo -e "Username: $Login"
    echo -e "Password: $Pass"
    echo -e "Created: $hariini"
    echo -e "Expired: $expi"
    echo -e "===========HOST-SSH==========="
    echo -e "IP/Host: $IP"
    echo -e "Domain SSH: $domain"
    echo -e "Domain Cloudflare: $domain"
    echo -e "Domain CloudFront: $cdndomain"
    echo -e "===========SLOWDNS==========="
    echo -e "Domain Name System(DNS): 8.8.8.8"
    echo -e "Name Server(NS): $sldomain"
    echo -e "DNS PUBLIC KEY: $slkey"
    echo -e "Domain SlowDNS: $sldomain"
    echo -e "=========Service-Port========="
    echo -e "SlowDNS: 443,22,109,143"
    echo -e "OpenSSH: 22"
    echo -e "Dropbear: 443, 109, 143"
    echo -e "SSL/TLS: 443"
    echo -e "SSH Websocket SSL/TLS: 443"
    echo -e "SSH Websocket HTTP: 8880"
    echo -e "BadVPN UDPGW: 7100,7200,7300"
    echo -e "Proxy CloudFront: [OFF]"
    echo -e "Proxy Squid: [OFF]"
    echo -e "OHP SSH: 8181"
    echo -e "OHP Dropbear: 8282"
    echo -e "OHP OpenVPN: 8383"
    echo -e "OVPN Websocket: 2086"
    echo -e "OVPN Port TCP: $ovpn"
    echo -e "OVPN Port UDP: $ovpn2"
    echo -e "OVPN Port SSL: 990"
    echo -e "OVPN TCP: http://$IP:89/tcp.ovpn"
    echo -e "OVPN UDP: http://$IP:89/udp.ovpn"
    echo -e "OVPN SSL: http://$IP:89/ssl.ovpn"
    echo -e "=============================="
    echo -e "SNI/Server Spoof: isi dengan bug"
    echo -e "Payload Websocket SSL/TLS"
    echo -e "=============================="
    echo -e "GET wss://bug.com/ HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
    echo -e "=============================="
    echo -e "Payload Websocket HTTP"
    echo -e "=============================="
    echo -e "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
    echo -e "=============================="
    echo -e "Script Mod By SL"
}

trialssh() {
    clear
    source /var/crot/ipvps.conf
    if [[ "$IP2" = "" ]]; then
        domain=$(cat /etc/xray/domain)
    else
        domain=$IP2
    fi
    clear
    IP=$(wget -qO- ipinfo.io/ip);
    ssl="$(cat ~/log-install.txt | grep -w "Stunnel5" | cut -d: -f2)"
    sqd="$(cat ~/log-install.txt | grep -w "Squid" | cut -d: -f2)"
    ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
    ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
    Login=Trial`</dev/urandom tr -dc X-Z0-9 | head -c4`
    hari="1"
    Pass=1
    clear
    systemctl restart ws-tls
    systemctl restart ws-nontls
    systemctl restart ssh-ohp
    systemctl restart dropbear-ohp
    systemctl restart openvpn-ohp
    useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
    exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    expi=`date -d "$masaaktif days" +"%Y-%m-%d"`
    echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
    echo -e ""
    echo -e "Informasi Trial SSH & OpenVPN"
    echo -e "================================"
    echo -e "IP/Host            : $IP"
    echo -e "Domain             : $domain"
    echo -e "Username           : $Login"
    echo -e "Password           : $Pass"
    echo -e "OpenSSH            : 443, 22"
    echo -e "Dropbear           : 443, 109, 143"
    echo -e "SSL/TLS            :$ssl"
    echo -e "Port Squid         :$sqd"
    echo -e "OHP SSH            : 8181"
    echo -e "OHP Dropbear       : 8282"
    echo -e "OHP OpenVPN        : 8383"
    echo -e "SSH Websocket SSL  : 443"
    echo -e "SSH Websocket HTTP : 8880"
    echo -e "OVPN Websocket     : 2086"
    echo -e "OVPN Port TCP      : $ovpn"
    echo -e "OVPN Port UDP      : $ovpn2"
    echo -e "OVPN Port SSL      : 990"
    echo -e "OVPN TCP           : http://$IP:89/tcp.ovpn"
    echo -e "OVPN UDP           : http://$IP:89/udp.ovpn"
    echo -e "OVPN SSL           : http://$IP:89/ssl.ovpn"
    echo -e "BadVpn             : 7100-7200-7300"
    echo -e "Created            : $hariini"
    echo -e "Expired            : $expi"
    echo -e "=============================="
    echo -e "Payload Websocket SSL/TLS"
    echo -e "=============================="
    echo -e "GET wss://bug.com [protocol][crlf]Host: ${domain}[crlf]Upgrade: websocket[crlf][crlf]"
    echo -e "=============================="
    echo -e "Payload Websocket HTTP"
    echo -e "=============================="
    echo -e "GET / HTTP/1.1[crlf]Host: ${domain}[crlf]Upgrade: websocket[crlf][crlf]"
    echo -e "=============================="
    echo -e "Script Mod By SL"
}

renewssh() {
    clear
    read -p "Username : " User
    egrep "^$User" /etc/passwd >/dev/null
    if [ $? -eq 0 ]; then
        read -p "Day Extend : " Days
        Today=`date +%s`
        Days_Detailed=$(( $Days * 86400 ))
        Expire_On=$(($Today + $Days_Detailed))
        Expiration=$(date -u --date="1970-01-01 $Expire_On sec GMT" +%Y/%m/%d)
        Expiration_Display=$(date -u --date="1970-01-01 $Expire_On sec GMT" '+%d %b %Y')
        passwd -u $User
        usermod -e  $Expiration $User
        egrep "^$User" /etc/passwd >/dev/null
        echo -e "$Pass\n$Pass\n"|passwd $User &> /dev/null
        clear
        echo -e ""
        echo -e "========================================"
        echo -e ""
        echo -e "    Username        :  $User"
        echo -e "    Days Added      :  $Days Days"
        echo -e "    Expires on      :  $Expiration_Display"
        echo -e ""
        echo -e "========================================"
    else
        clear
        echo -e ""
        echo -e "======================================"
        echo -e ""
        echo -e "        Username Doesnt Exist        "
        echo -e ""
        echo -e "======================================"
    fi
}

cekssh() {
    clear
    if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log"
    fi
    if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure"
    fi
                
    data=( `ps aux | grep -i dropbear | awk '{print $2}'`)
    echo "----------=[ Dropbear User Login ]=-----------"
    echo "ID  |  Username  |  IP Address"
    echo "----------------------------------------------"
    cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/login-db.txt
    for PID in "${data[@]}"
    do
        cat /tmp/login-db.txt | grep "dropbear\[$PID\]" > /tmp/login-db-pid.txt
        NUM=`cat /tmp/login-db-pid.txt | wc -l`
        USER=`cat /tmp/login-db-pid.txt | awk '{print $10}'`
        IP=`cat /tmp/login-db-pid.txt | awk '{print $12}'`
        if [ $NUM -eq 1 ]; then
            echo "$PID - $USER - $IP"
        fi
    done
    echo " "
    echo "----------=[ OpenSSH User Login ]=------------"
    echo "ID  |  Username  |  IP Address"
    echo "----------------------------------------------"
    cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/login-db.txt
    data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`)

    for PID in "${data[@]}"
    do
        cat /tmp/login-db.txt | grep "sshd\[$PID\]" > /tmp/login-db-pid.txt
        NUM=`cat /tmp/login-db-pid.txt | wc -l`
        USER=`cat /tmp/login-db-pid.txt | awk '{print $9}'`
        IP=`cat /tmp/login-db-pid.txt | awk '{print $11}'`
        if [ $NUM -eq 1 ]; then
            echo "$PID - $USER - $IP"
        fi
    done
    if [ -f "/etc/openvpn/server/openvpn-tcp.log" ]; then
        echo ""
        echo "---------=[ OpenVPN TCP User Login ]=---------"
        echo "Username  |  IP Address  |  Connected"
        echo "----------------------------------------------"
        cat /etc/openvpn/server/openvpn-tcp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-tcp.txt
        cat /tmp/vpn-login-tcp.txt
    fi
    echo "----------------------------------------------"

    if [ -f "/etc/openvpn/server/openvpn-udp.log" ]; then
        echo " "
        echo "---------=[ OpenVPN UDP User Login ]=---------"
        echo "Username  |  IP Address  |  Connected"
        echo "----------------------------------------------"
        cat /etc/openvpn/server/openvpn-udp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-udp.txt
        cat /tmp/vpn-login-udp.txt
    fi
    echo "----------------------------------------------"
    echo "Script Mod By SL"
    echo ""
}

member() {
    clear
    echo "---------------------------------------------------"
    echo "USERNAME          EXP DATE          STATUS"
    echo "---------------------------------------------------"
    while read expired
    do
        AKUN="$(echo $expired | cut -d: -f1)"
        ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
        exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
        status="$(passwd -S $AKUN | awk '{print $2}' )"
        if [[ $ID -ge 1000 ]]; then
            if [[ "$status" = "L" ]]; then
                printf "%-17s %2s %-17s %2s \n" "$AKUN" "$exp     " "${RED}LOCKED${NORMAL}"
            else
                printf "%-17s %2s %-17s %2s \n" "$AKUN" "$exp     " "${GREEN}UNLOCKED${NORMAL}"
            fi
        fi
    done < /etc/passwd
    JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
    echo "---------------------------------------------------"
    echo "Account number: $JUMLAH user"
    echo "---------------------------------------------------"
}

delssh() {
    clear
    read -p "Username SSH to Delete : " Pengguna

    if getent passwd $Pengguna > /dev/null 2>&1; then
        userdel $Pengguna
        echo -e "Username $Pengguna Telah Di Hapus"
    else
        echo -e "Failure: Username $Pengguna Tidak Ada"
    fi
}

delexp() {
    clear
    hariini=`date +%d-%m-%Y`
    echo "Thank you for removing the EXPIRED USERS"
    echo "--------------------------------------"
    cat /etc/shadow | cut -d: -f1,8 | sed /:$/d > /tmp/expirelist.txt
    totalaccounts=`cat /tmp/expirelist.txt | wc -l`
    for((i=1; i<=$totalaccounts; i++ ))
    do
        tuserval=`head -n $i /tmp/expirelist.txt | tail -n 1`
        username=`echo $tuserval | cut -f1 -d:`
        userexp=`echo $tuserval | cut -f2 -d:`
        userexpireinseconds=$(( $userexp * 86400 ))
        tglexp=`date -d @$userexpireinseconds`             
        tgl=`echo $tglexp |awk -F" " '{print $3}'`
        while [ ${#tgl} -lt 2 ]
        do
            tgl="0"$tgl
        done
        while [ ${#username} -lt 15 ]
        do
            username=$username" " 
        done
        bulantahun=`echo $tglexp |awk -F" " '{print $2,$6}'`
        echo "echo "Expired- User : $username Expire at : $tgl $bulantahun"" >> /usr/local/bin/alluser
        todaystime=`date +%s`
        if [ $userexpireinseconds -ge $todaystime ] ; then
            :
        else
            echo "echo "Expired- Username : $username are expired at: $tgl $bulantahun and removed : $hariini "" >> /usr/local/bin/deleteduser
            echo "Username $username that are expired at $tgl $bulantahun removed from the VPS $hariini"
            userdel $username
        fi
    done
    echo " "
    echo "--------------------------------------"
    echo "Script are successfully run"
}

autokill() {
    clear
    Green_font_prefix="\033[32m" 
    Red_font_prefix="\033[31m" 
    Green_background_prefix="\033[42;37m" 
    Red_background_prefix="\033[41;37m" 
    Font_color_suffix="\033[0m"
    Info="${Green_font_prefix}[ON]${Font_color_suffix}"
    Error="${Red_font_prefix}[OFF]${Font_color_suffix}"
    cek=$(grep -c -E "^# Autokill" /etc/cron.d/tendang)
    if [[ "$cek" = "1" ]]; then
        sts="${Info}"
    else
        sts="${Error}"
    fi
    clear
    echo -e ""
    echo -e "=================================="
    echo -e "       Status Autokill $sts       "
    echo -e "=================================="
    echo -e "1. AutoKill After 5 Minutes"
    echo -e "2. AutoKill After 10 Minutes"
    echo -e "3. AutoKill After 15 Minutes"
    echo -e "4. Turn Off AutoKill/MultiLogin"
    echo -e "5. Exit"
    echo -e "=================================="                                                                                                          
    echo -e ""
    read -p "Select From Options [1-4 or x] :  " AutoKill
    read -p "Multilogin Maximum Number Of Allowed: " max
    echo -e ""
    case $AutoKill in
        1)
            echo -e ""
            sleep 1
            clear
            echo > /etc/cron.d/tendang
            echo "# Autokill" >>/etc/cron.d/tendang
            echo "*/5 * * * *  root /usr/bin/tendang $max" >>/etc/cron.d/tendang
            echo -e ""
            echo -e "======================================"
            echo -e ""
            echo -e "      Allowed MultiLogin : $max"
            echo -e "      AutoKill Every     : 5 Minutes"      
            echo -e ""
            echo -e "======================================"                                                                                                                                 
            exit                                                                  
            ;;
        2)
            echo -e ""
            sleep 1
            clear
            echo > /etc/cron.d/tendang
            echo "# Autokill" >>/etc/cron.d/tendang
            echo "*/10 * * * *  root /usr/bin/tendang $max" >>/etc/cron.d/tendang
            echo -e ""
            echo -e "======================================"
            echo -e ""
            echo -e "      Allowed MultiLogin : $max"
            echo -e "      AutoKill Every     : 10 Minutes"
            echo -e ""
            echo -e "======================================"
            exit
            ;;
        3)
            echo -e ""
            sleep 1
            clear
            echo > /etc/cron.d/tendang
            echo "# Autokill" >>/etc/cron.d/tendang
            echo "*/15 * * * *  root /usr/bin/tendang $max" >>/etc/cron.d/tendang
            echo -e ""
            echo -e "======================================"
            echo -e ""
            echo -e "      Allowed MultiLogin : $max"
            echo -e "      AutoKill Every     : 15 Minutes"
            echo -e ""
            echo -e "======================================"
            exit
            ;;
        4)
            clear
            echo > /etc/cron.d/tendang
            echo -e ""
            echo -e "======================================"
            echo -e ""
            echo -e "      AutoKill MultiLogin Turned Off  "
            echo -e ""
            echo -e "======================================"
            exit
            ;;
        x)
            clear
            exit
            ;;
    esac
}

ceklim() {
    clear
    echo " "
    echo "==========================================="
    echo " "
    if [ -e "/root/log-limit.txt" ]; then
        echo "User Who Violate The Maximum Limit"
        echo "Time - Username - Number of Multilogin"
        echo "-------------------------------------"
        cat /root/log-limit.txt
    else
        echo " No user has committed a violation"
        echo " "
        echo " or"
        echo " "
        echo " The user-limit script not been executed."
    fi
    echo " "
    echo "==========================================="
    echo " "
}

restart() {
    clear
    echo -e ""
    echo -e "Starting Restart All Service"
    sleep 2
    systemctl stop ws-tls
    systemctl start sslh
    systemctl restart sslh
    /etc/init.d/sslh start
    /etc/init.d/sslh restart
    systemctl restart ssrmu
    systemctl restart ws-tls
    systemctl restart ws-nontls
    systemctl restart xray.service
    systemctl restart vless-grpc
    systemctl restart vmess-grpc
    systemctl restart shadowsocks-libev
    systemctl restart xl2tpd
    systemctl restart pptpd
    systemctl restart ipsec
    systemctl restart accel-ppp
    systemctl restart ws-ovpn
    systemctl restart wg-quick@wg0
    systemctl restart ssh-ohp
    systemctl restart dropbear-ohp
    systemctl restart openvpn-ohp
    systemctl restart trojan-go
    /etc/init.d/ssrmu restart
    /etc/init.d/ssh restart
    /etc/init.d/dropbear restart
    /etc/init.d/sslh restart
    /etc/init.d/stunnel5 restart
    /etc/init.d/stunnel4 restart
    /etc/init.d/openvpn restart
    /etc/init.d/fail2ban restart
    /etc/init.d/cron restart
    /etc/init.d/nginx restart
    /etc/init.d/squid restart
    screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000
    screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000
    screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000
    echo -e "Restart All Service Berhasil"
}

# Xray Vmess Functions
addvmess() {
    source /var/lib/crot/ipvps.conf
    if [[ "$IP" = "" ]]; then
        domain=$(cat /etc/xray/domain)
    else
        domain=$IP
    fi
    tls="$(cat ~/log-install.txt | grep -w "Vmess TLS" | cut -d: -f2|sed 's/ //g')"
    nontls="$(cat ~/log-install.txt | grep -w "Vmess None TLS" | cut -d: -f2|sed 's/ //g')"
    until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
        read -rp "Username : " -e user
        CLIENT_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

        if [[ ${CLIENT_EXISTS} == '1' ]]; then
            echo ""
            echo -e "Username ${RED}${CLIENT_NAME}${NC} Already On VPS Please Choose Another"
            exit 1
        fi
    done
    uuid=$(cat /proc/sys/kernel/random/uuid)
    read -p "Expired (Days) : " masaaktif
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    sed -i '/#xray-vmess-tls$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"32"',"email": "'""$user""'"' /etc/xray/config.json
    sed -i '/#xray-vmess-nontls$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"32"',"email": "'""$user""'"' /etc/xray/config.json
    cat>/etc/xray/vmess-$user-tls.json<<EOF
    {
    "v": "2",
    "ps": "${user}",
    "add": "${domain}",
    "port": "${tls}",
    "id": "${uuid}",
    "aid": "0",
    "net": "ws",
    "path": "/vmess/",
    "type": "none",
    "host": "",
    "tls": "tls"
}
EOF
    cat>/etc/xray/vmess-$user-nontls.json<<EOF
    {
    "v": "2",
    "ps": "${user}",
    "add": "${domain}",
    "port": "${nontls}",
    "id": "${uuid}",
    "aid": "0",
    "net": "ws",
    "path": "/vmess/",
    "type": "none",
    "host": "",
    "tls": "none"
}
EOF
    vmess_base641=$( base64 -w 0 <<< $vmess_json1)
    vmess_base642=$( base64 -w 0 <<< $vmess_json2)
    xrayv2ray1="vmess://$(base64 -w 0 /etc/xray/vmess-$user-tls.json)"
    xrayv2ray2="vmess://$(base64 -w 0 /etc/xray/vmess-$user-nontls.json)"
    systemctl restart xray.service
    service cron restart
    clear
    echo -e ""
    echo -e "======-XRAYS/VMESS-======"
    echo -e "Remarks     : ${user}"
    echo -e "IP/Host     : ${MYIP}"
    echo -e "Address     : ${domain}"
    echo -e "Port TLS    : ${tls}"
    echo -e "Port No TLS : ${nontls}"
    echo -e "User ID     : ${uuid}"
    echo -e "Alter ID    : 0"
    echo -e "Security    : auto"
    echo -e "Network     : ws"
    echo -e "Path        : /vmess/"
    echo -e "Created     : $hariini"
    echo -e "Expired     : $exp"
    echo -e "========================="
    echo -e "Link TLS    : ${xrayv2ray1}"
    echo -e "========================="
    echo -e "Link No TLS : ${xrayv2ray2}"
    echo -e "========================="
    echo -e "Script Mod By SL"
}

delvmess() {
    clear
    NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/config.json")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    clear
    echo ""
    echo " Select the existing client you want to remove"
    echo " Press CTRL+C to return"
    echo " ==============================="
    echo "     No  Expired   User"
    grep -E "^### " "/etc/xray/config.json" | cut -d ' ' -f 2-3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done
    user=$(grep -E "^### " "/etc/xray/config.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^### " "/etc/xray/config.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    sed -i "/^### $user $exp/,/^},{/d" /etc/xray/config.json
    sed -i "/^### $user $exp/,/^},{/d" /etc/xray/config.json
    rm -f /etc/xray/vmess-$user-tls.json /etc/xray/vmess-$user-nontls.json
    systemctl restart xray.service
    clear
    echo ""
    echo "==============================="
    echo "  XRAYS/Vmess Account Deleted  "
    echo "==============================="
    echo "Username  : $user"
    echo "Expired   : $exp"
    echo "==============================="
    echo "Script Mod By SL"
}

renewvmess() {
    clear
    NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/config.json")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        clear
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    clear
    echo ""
    echo "Select the existing client you want to renew"
    echo " Press CTRL+C to return"
    echo -e "==============================="
    grep -E "^### " "/etc/xray/config.json" | cut -d ' ' -f 2-3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done
    read -p "Expired (Days): " masaaktif
    user=$(grep -E "^### " "/etc/xray/config.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^### " "/etc/xray/config.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    now=$(date +%Y-%m-%d)
    d1=$(date -d "$exp" +%s)
    d2=$(date -d "$now" +%s)
    exp2=$(( (d1 - d2) / 86400 ))
    exp3=$(($exp2 + $masaaktif))
    exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
    sed -i "s/### $user $exp/### $user $exp4/g" /etc/xray/config.json
    sed -i "s/### $user $exp/### $user $exp4/g" /etc/xray/config.json
    systemctl restart xray.service
    service cron restart
    clear
    echo ""
    echo "==============================="
    echo "  XRAYS/Vmess Account Renewed  "
    echo "==============================="
    echo "Username  : $user"
    echo "Expired   : $exp4"
    echo "==============================="
    echo "Script Mod By SL"
}

cekvmess() {
    clear
    echo -n > /tmp/other.txt
    data=( `cat /etc/xray/config.json | grep '^###' | cut -d ' ' -f 2`);
    echo "----------------------------------------";
    echo "---------=[ Vmess User Login ]=---------";
    echo "----------------------------------------";
    for akun in "${data[@]}"
    do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n > /tmp/ipvmess.txt
        data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
        for ip in "${data2[@]}"
        do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >> /tmp/ipvmess.txt
            else
                echo "$ip" >> /tmp/other.txt
            fi
            jum2=$(cat /tmp/ipvmess.txt)
            sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
        done
        jum=$(cat /tmp/ipvmess.txt)
        if [[ -z "$jum" ]]; then
            echo > /dev/null
        else
            jum2=$(cat /tmp/ipvmess.txt | nl)
            echo "user : $akun";
            echo "$jum2";
            echo "----------------------------------------"
        fi
        rm -rf /tmp/ipvmess.txt
    done
    oth=$(cat /tmp/other.txt | sort | uniq | nl)
    echo "other";
    echo "$oth";
    echo "----------------------------------------"
    echo "Script Mod By SL"
    rm -rf /tmp/other.txt
}

certv2ray() {
    clear
    echo start
    sleep 0.5
    source /var/lib/crot/ipvps.conf
    domain=$(cat /etc/xray/domain)
    sudo lsof -t -i tcp:80 -s tcp:listen | sudo xargs kill
    cd /root/
    wget -O acme.sh https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh
    bash acme.sh --install
    rm acme.sh
    cd .acme.sh
    echo "starting...., Port 80 Akan di Hentikan Saat Proses install Cert"
    bash acme.sh --register-account -m kimochilol@gmail.com
    bash acme.sh --issue --standalone -d $domain --force
    bash acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key
}

# Xray Vless Functions
addvless() {
    source /var/lib/crot/ipvps.conf
    if [[ "$IP" = "" ]]; then
        domain=$(cat /etc/xray/domain)
    else
        domain=$IP
    fi
    tls="$(cat ~/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
    nontls="$(cat ~/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"
    until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
        read -rp "Username : " -e user
        CLIENT_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

        if [[ ${CLIENT_EXISTS} == '1' ]]; then
            echo ""
            echo -e "Username ${RED}${user}${NC} Already On VPS Please Choose Another"
            exit 1
        fi
    done
    uuid=$(cat /proc/sys/kernel/random/uuid)
    read -p "Expired (Days) : " masaaktif
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    sed -i '/#xray-vless-tls$/a\#### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
    sed -i '/#xray-vless-nontls$/a\#### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
    xrayvless1="vless://${uuid}@${domain}:$tls?path=/vless/&security=tls&encryption=none&type=ws#${user}"
    xrayvless2="vless://${uuid}@${domain}:$nontls?path=/vless/&encryption=none&type=ws#${user}"
    systemctl restart xray.service
    service cron restart
    clear
    echo -e ""
    echo -e "======-XRAYS/VLESS-======"
    echo -e "Remarks     : ${user}"
    echo -e "IP/Host     : ${MYIP}"
    echo -e "Address     : ${domain}"
    echo -e "Port TLS    : $tls"
    echo -e "Port No TLS : $nontls"
    echo -e "User ID     : ${uuid}"
    echo -e "Encryption  : none"
    echo -e "Network     : ws"
    echo -e "Path        : /vless/"
    echo -e "Created     : $hariini"
    echo -e "Expired     : $exp"
    echo -e "========================="
    echo -e "Link TLS    : ${xrayvless1}"
    echo -e "========================="
    echo -e "Link No TLS : ${xrayvless2}"
    echo -e "========================="
    echo -e "Script Mod By SL"
}

delvless() {
    clear
    NUMBER_OF_CLIENTS=$(grep -c -E "^#### " "/etc/xray/config.json")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    clear
    echo ""
    echo " Select the existing client you want to remove"
    echo " Press CTRL+C to return"
    echo " ==============================="
    echo "     No  Expired   User"
    grep -E "^#### " "/etc/xray/config.json" | cut -d ' ' -f 2-3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done
    user=$(grep -E "^#### " "/etc/xray/config.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^#### " "/etc/xray/config.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    sed -i "/^#### $user $exp/,/^},{/d" /etc/xray/config.json
    sed -i "/^#### $user $exp/,/^},{/d" /etc/xray/config.json
    systemctl restart xray.service
    service cron restart
    clear
    echo ""
    echo "==============================="
    echo "  XRAYS/Vless Account Deleted  "
    echo "==============================="
    echo "Username  : $user"
    echo "Expired   : $exp"
    echo "==============================="
    echo "Script Mod By SL"
}

renewvless() {
    clear
    NUMBER_OF_CLIENTS=$(grep -c -E "^#### " "/etc/xray/config.json")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        clear
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    clear
    echo ""
    echo "Select the existing client you want to renew"
    echo " Press CTRL+C to return"
    echo -e "==============================="
    grep -E "^#### " "/etc/xray/config.json" | cut -d ' ' -f 2-3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done
    read -p "Expired (Days) : " masaaktif
    user=$(grep -E "^#### " "/etc/xray/config.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^#### " "/etc/xray/config.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    now=$(date +%Y-%m-%d)
    d1=$(date -d "$exp" +%s)
    d2=$(date -d "$now" +%s)
    exp2=$(( (d1 - d2) / 86400 ))
    exp3=$(($exp2 + $masaaktif))
    exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
    sed -i "s/#### $user $exp/#### $user $exp4/g" /etc/xray/config.json
    sed -i "s/#### $user $exp/#### $user $exp4/g" /etc/xray/config.json
    service cron restart
    clear
    echo ""
    echo "==============================="
    echo "  XRAYS/Vless Account Renewed  "
    echo "==============================="
    echo "Username  : $user"
    echo "Expired   : $exp4"
    echo "==============================="
    echo "Script Mod By SL"
}

cekvless() {
    clear
    echo -n > /tmp/other.txt
    data=( `cat /etc/xray/config.json | grep '^####' | cut -d ' ' -f 2`);
    echo "----------------------------------------";
    echo "---------=[ Vless User Login ]=---------";
    echo "----------------------------------------";
    for akun in "${data[@]}"
    do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n > /tmp/ipvless.txt
        data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
        for ip in "${data2[@]}"
        do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >> /tmp/ipvless.txt
            else
                echo "$ip" >> /tmp/other.txt
            fi
            jum2=$(cat /tmp/ipvless.txt)
            sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
        done
        jum=$(cat /tmp/ipvless.txt)
        if [[ -z "$jum" ]]; then
            echo > /dev/null
        else
            jum2=$(cat /tmp/ipvless.txt | nl)
            echo "user : $akun";
            echo "$jum2";
            echo "----------------------------------------"
        fi
        rm -rf /tmp/ipvless.txt
    done
    oth=$(cat /tmp/other.txt | sort | uniq | nl)
    echo "other";
    echo "$oth";
    echo "----------------------------------------"
    echo "Script Mod By SL"
    rm -rf /tmp/other.txt
}

# Xray Trojan Functions
addtrojan() {
    source /var/lib/crot/ipvps.conf
    if [[ "$IP" = "" ]]; then
        domain=$(cat /etc/xray/domain)
    else
        domain=$IP
    fi
    tr="$(cat ~/log-install.txt | grep -w "Trojan" | cut -d: -f2|sed 's/ //g')"
    until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${user_EXISTS} == '0' ]]; do
        read -rp "Password : " -e user
        user_EXISTS=$(grep -w $user /etc/xray/config.json | wc -l)

        if [[ ${user_EXISTS} == '1' ]]; then
            echo ""
            echo -e "Username ${RED}${user}${NC} Already On VPS Please Choose Another"
            exit 1
        fi
    done
    read -p "Expired (Days) : " masaaktif
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    sed -i '/#xray-trojan$/a\#&# '"$user $exp"'\
},{"password": "'""$user""'","email": "'""$user""'"' /etc/xray/config.json
    systemctl restart xray.service
    trojanlink="trojan://${user}@${domain}:${tr}"
    service cron restart
    clear
    echo -e ""
    echo -e "======-XRAYS/TROJAN-======"
    echo -e "Remarks  : ${user}"
    echo -e "IP/Host  : ${MYIP}"
    echo -e "Address  : ${domain}"
    echo -e "Port     : ${tr}"
    echo -e "Key      : ${user}"
    echo -e "Created  : $hariini"
    echo -e "Expired  : $exp"
    echo -e "=========================="
    echo -e "Link TR  : ${trojanlink}"
    echo -e "=========================="
    echo -e "Script Mod By SL"
}

deltrojan() {
    clear
    NUMBER_OF_CLIENTS=$(grep -c -E "^#&# " "/etc/xray/config.json")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    echo ""
    echo " Select the existing client you want to remove"
    echo " Press CTRL+C to return"
    echo " ==============================="
    echo "     No  Expired   User"
    grep -E "^#&# " "/etc/xray/config.json" | cut -d ' ' -f 2-3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done
    user=$(grep -E "^#&# " "/etc/xray/config.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^#&# " "/etc/xray/config.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    sed -i "/^#&# $user $exp/,/^},{/d" /etc/xray/config.json
    sed -i "/^#&# $user $exp/,/^},{/d" /etc/xray/config.json
    systemctl restart xray.service
    service cron restart
    clear
    echo ""
    echo "================================"
    echo "  XRAYS/Trojan Account Deleted  "
    echo "================================"
    echo "Username  : $user"
    echo "Expired   : $exp"
    echo "================================"
    echo "Script Mod By SL"
}

renewtrojan() {
    clear
    NUMBER_OF_CLIENTS=$(grep -c -E "^#&# " "/etc/xray/config.json")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        clear
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    clear
    echo ""
    echo "Select the existing client you want to renew"
    echo " Press CTRL+C to return"
    echo -e "==============================="
    grep -E "^#&# " "/etc/xray/config.json" | cut -d ' ' -f 2-3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done
    read -p "Expired (Days) : " masaaktif
    user=$(grep -E "^#&# " "/etc/xray/config.json" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^#&# " "/etc/xray/config.json" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    now=$(date +%Y-%m-%d)
    d1=$(date -d "$exp" +%s)
    d2=$(date -d "$now" +%s)
    exp2=$(( (d1 - d2) / 86400 ))
    exp3=$(($exp2 + $masaaktif))
    exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
    sed -i "s/#&# $user $exp/#&# $user $exp4/g" /etc/xray/config.json
    clear
    echo ""
    echo "================================"
    echo "  XRAYS/Trojan Account Renewed  "
    echo "================================"
    echo "Username  : $user"
    echo "Expired  : $exp4"
    echo "================================"
    echo "Script Mod By SL"
}

cektrojan() {
    clear
    echo -n > /tmp/other.txt
    data=( `cat /etc/xray/config.json | grep '^#&#' | cut -d ' ' -f 2`);
    echo "-----------------------------------------";
    echo "---------=[ Trojan User Login ]=---------";
    echo "-----------------------------------------";
    for akun in "${data[@]}"
    do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n > /tmp/iptrojan.txt
        data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
        for ip in "${data2[@]}"
        do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >> /tmp/iptrojan.txt
            else
                echo "$ip" >> /tmp/other.txt
            fi
            jum2=$(cat /tmp/iptrojan.txt)
            sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
        done
        jum=$(cat /tmp/iptrojan.txt)
        if [[ -z "$jum" ]]; then
            echo > /dev/null
        else
            jum2=$(cat /tmp/iptrojan.txt | nl)
            echo "user : $akun";
            echo "$jum2";
            echo "-----------------------------------------"
        fi
        rm -rf /tmp/iptrojan.txt
    done
    oth=$(cat /tmp/other.txt | sort | uniq | nl)
    echo "other";
    echo "$oth";
    echo "-----------------------------------------"
    echo "Script Mod By SL"
    rm -rf /tmp/other.txt
}

# Shadowsocks Functions
addss() {
    clear
    IP=$(wget -qO- ipinfo.io/ip);
    lastport1=$(grep "port_tls" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
    lastport2=$(grep "port_http" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
    if [[ $lastport1 == '' ]]; then
        tls=2443
    else
        tls="$((lastport1+1))"
    fi
    if [[ $lastport2 == '' ]]; then
        http=3443
    else
        http="$((lastport2+1))"
    fi
    source /var/lib/crot/ipvps.conf
    if [[ "$IP2" = "" ]]; then
        domain=$(cat /etc/xray/domain)
    else
        domain=$IP2
    fi

    #Default
    cat > /etc/shadowsocks-libev/tls.json<<END
{   
    "server":"0.0.0.0",
    "server_port":$tls,
    "password":"tls",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
END
    cat > /etc/shadowsocks-libev/http.json <<-END
{
    "server":"0.0.0.0",
    "server_port":$http,
    "password":"http",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http"
}
END
    chmod +x /etc/shadowsocks-libev/tls.json
    chmod +x /etc/shadowsocks-libev/http.json

    systemctl enable shadowsocks-libev-server@tls.service
    systemctl start shadowsocks-libev-server@tls.service
    systemctl enable shadowsocks-libev-server@http.service
    systemctl start shadowsocks-libev-server@http.service
    #
    echo ""
    echo "Masukkan Password"

    until [[ $user =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
        read -rp "Password : " -e user
        CLIENT_EXISTS=$(grep -w $user /etc/shadowsocks-libev/akun.conf | wc -l)

        if [[ ${CLIENT_EXISTS} == '1' ]]; then
            echo ""
            echo -e "Username ${RED}${user}${NC} Already On VPS Please Choose Another"
            exit 1
        fi
    done
    read -p "Expired (Days) : " masaaktif
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
    cat > /etc/shadowsocks-libev/$user-tls.json<<END
{   
    "server":"0.0.0.0",
    "server_port":$tls,
    "password":"$user",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
END
    cat > /etc/shadowsocks-libev/$user-http.json <<-END
{
    "server":"0.0.0.0",
    "server_port":$http,
    "password":"$user",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http"
}
END
    chmod +x /etc/shadowsocks-libev/$user-tls.json
    chmod +x /etc/shadowsocks-libev/$user-http.json

    systemctl enable shadowsocks-libev-server@$user-tls.service
    systemctl start shadowsocks-libev-server@$user-tls.service
    systemctl enable shadowsocks-libev-server@$user-http.service
    systemctl start shadowsocks-libev-server@$user-http.service
    tmp1=$(echo -n "aes-256-cfb:${user}@${MYIP}:$tls" | base64 -w0)
    tmp2=$(echo -n "aes-256-cfb:${user}@${MYIP}:$http" | base64 -w0)
    linkss1="ss://${tmp1}?plugin=obfs-local;obfs=tls;obfs-host=bing.com"
    linkss2="ss://${tmp2}?plugin=obfs-local;obfs=http;obfs-host=bing.com"
    echo -e "### $user $exp
port_tls $tls
port_http $http">>"/etc/shadowsocks-libev/akun.conf"
    service cron restart
    clear
    echo -e ""
    echo -e "======-SHADOWSOCKS-======"
    echo -e "IP/Host     : $MYIP"
    echo -e "Domain      : $domain"
    echo -e "Port TLS    : $tls"
    echo -e "Port No TLS : $http"
    echo -e "Password    : $user"
    echo -e "Method      : aes-256-cfb"
    echo -e "Created     : $hariini"
    echo -e "Expired     : $exp"
    echo -e "========================="
    echo -e "Link TLS    : $linkss1"
    echo -e "========================="
    echo -e "Link No TLS : $linkss2"
    echo -e "========================="
    echo -e "Script Mod By SL"
}

delss() {
    clear
    NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/shadowsocks-libev/akun.conf")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        clear
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    clear
    echo ""
    echo " Select the existing client you want to remove"
    echo " Press CTRL+C to return"
    echo " ==============================="
    echo "     No  Expired   User"
    grep -E "^### " "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f 2-3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Pilih salah satu[1]: " CLIENT_NUMBER
        else
            read -rp "Pilih salah satu [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done
    # match the selected number to a client name
    CLIENT_NAME=$(grep -E "^### " "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f 2-3 | sed -n "${CLIENT_NUMBER}"p)
    user=$(grep -E "^### " "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^### " "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    # remove [Peer] block matching $CLIENT_NAME
    sed -i "/^### $user $exp/,/^port_http/d" "/etc/shadowsocks-libev/akun.conf"
    # remove generated client file
    service cron restart
    systemctl disable shadowsocks-libev-server@$user-tls.service
    systemctl disable shadowsocks-libev-server@$user-http.service
    systemctl stop shadowsocks-libev-server@$user-tls.service
    systemctl stop shadowsocks-libev-server@$user-http.service
    # disable
    systemctl disable shadowsocks-libev-server@$user-tls.service
    systemctl disable shadowsocks-libev-server@$user-http.service
    systemctl disable shadowsocks-libev-server@$user-v2rayws.service
    systemctl disable shadowsocks-libev-server@$user-v2raywss.service
    systemctl disable shadowsocks-libev-server@$user-v2rayquic.service
    systemctl disable shadowsocks-libev-server@$user-v2raygrpc.service
    systemctl disable shadowsocks-libev-server@$user-xrayws.service
    systemctl disable shadowsocks-libev-server@$user-xraywss.service
    systemctl disable shadowsocks-libev-server@$user-xraygrpctls.service
    systemctl disable shadowsocks-libev-server@$user-xraygrpchttp.service
    systemctl disable shadowsocks-libev-server@$user-xrayquic.service
    systemctl disable shadowsocks-libev-server@$user-gostls.service
    systemctl disable shadowsocks-libev-server@$user-gostmtls.service
    systemctl disable shadowsocks-libev-server@$user-gostxtls.service
    systemctl disable shadowsocks-libev-server@$user-gostgrpc.service
    systemctl disable shadowsocks-libev-server@$user-gostws.service
    systemctl disable shadowsocks-libev-server@$user-gostwss.service
    systemctl disable shadowsocks-libev-server@$user-gostmws.service
    systemctl disable shadowsocks-libev-server@$user-gostmwss.service
    systemctl disable shadowsocks-libev-server@$user-gostquic.service
    systemctl disable shadowsocks-libev-server@$user-gosth2.service
    # stop
    systemctl stop shadowsocks-libev-server@$user-tls.service
    systemctl stop shadowsocks-libev-server@$user-http.service
    systemctl stop shadowsocks-libev-server@$user-v2rayws.service
    systemctl stop shadowsocks-libev-server@$user-v2raywss.service
    systemctl stop shadowsocks-libev-server@$user-v2rayquic.service
    systemctl stop shadowsocks-libev-server@$user-v2raygrpc.service
    systemctl stop shadowsocks-libev-server@$user-xrayws.service
    systemctl stop shadowsocks-libev-server@$user-xraywss.service
    systemctl stop shadowsocks-libev-server@$user-xraygrpctls.service
    systemctl stop shadowsocks-libev-server@$user-xraygrpchttp.service
    systemctl stop shadowsocks-libev-server@$user-xrayquic.service
    systemctl stop shadowsocks-libev-server@$user-gostls.service
    systemctl stop shadowsocks-libev-server@$user-gostmtls.service
    systemctl stop shadowsocks-libev-server@$user-gostxtls.service
    systemctl stop shadowsocks-libev-server@$user-gostgrpc.service
    systemctl stop shadowsocks-libev-server@$user-gostws.service
    systemctl stop shadowsocks-libev-server@$user-gostwss.service
    systemctl stop shadowsocks-libev-server@$user-gostmws.service
    systemctl stop shadowsocks-libev-server@$user-gostmwss.service
    systemctl stop shadowsocks-libev-server@$user-gostquic.service
    systemctl stop shadowsocks-libev-server@$user-gosth2.service
    # hapus akun
    rm -f "/etc/shadowsocks-libev/$user-tls.json"
    rm -f "/etc/shadowsocks-libev/$user-http.json"
    rm -f "/etc/shadowsocks-libev/$user-v2rayws.json"
    rm -f "/etc/shadowsocks-libev/$user-v2raywss.json"
    rm -f "/etc/shadowsocks-libev/$user-v2rayquic.json"
    rm -f "/etc/shadowsocks-libev/$user-v2raygrpc.json"
    rm -f "/etc/shadowsocks-libev/$user-xrayws.json"
    rm -f "/etc/shadowsocks-libev/$user-xraywss.json"
    rm -f "/etc/shadowsocks-libev/$user-xraygrpctls.json"
    rm -f "/etc/shadowsocks-libev/$user-xraygrpchttp.json"
    rm -f "/etc/shadowsocks-libev/$user-xrayquic.json"
    rm -f "/etc/shadowsocks-libev/$user-gosttls.json"
    rm -f "/etc/shadowsocks-libev/$user-gostmtls.json"
    rm -f "/etc/shadowsocks-libev/$user-gostxtls.json"
    rm -f "/etc/shadowsocks-libev/$user-gostgrpc.json"
    rm -f "/etc/shadowsocks-libev/$user-gostws.json"
    rm -f "/etc/shadowsocks-libev/$user-gostwss.json"
    rm -f "/etc/shadowsocks-libev/$user-gostmws.json"
    rm -f "/etc/shadowsocks-libev/$user-gostmwss.json"
    rm -f "/etc/shadowsocks-libev/$user-gostquic.json"
    rm -f "/etc/shadowsocks-libev/$user-gosth2.json"
    rm -f "/home/vps/public_html/$user.json"
    clear
    echo ""
    echo "==========================="
    echo "  SS OBFS Account Deleted  "
    echo "==========================="
    echo "Username  : $user"
    echo "Expired   : $exp"
    echo "==========================="
    echo "Script Mod By SL"
}

renewss() {
    clear
    NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/shadowsocks-libev/akun.conf")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        clear
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    clear
    echo ""
    echo "Select the existing client you want to renew"
    echo " Press CTRL+C to return"
    echo -e "==============================="
    grep -E "^### " "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f 2-3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done
    read -p "Expired (Days): " masaaktif
    user=$(grep -E "^### " "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^### " "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    now=$(date +%Y-%m-%d)
    d1=$(date -d "$exp" +%s)
    d2=$(date -d "$now" +%s)
    exp2=$(( (d1 - d2) / 86400 ))
    exp3=$(($exp2 + $masaaktif))
    exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
    sed -i "s/### $user $exp/### $user $exp4/g" /etc/shadowsocks-libev/akun.conf
    clear
    echo ""
    echo "==========================="
    echo "  SS OBFS Account Renewed  "
    echo "==========================="
    echo "Username  : $user"
    echo "Expired   : $exp4"
    echo "==========================="
    echo "Script Mod By SL"
}

cekss() {
    clear
    echo "----------------------------------"
    echo "----=[ SS - OBFS User Login ]=----"
    echo "----------------------------------"
    echo ""
    data=( `cat /etc/shadowsocks-libev/akun.conf | grep '^###' | cut -d ' ' -f 2`)
    x=1
    echo "----------------------------------"
    echo " User | TLS"
    echo "----------------------------------"
    for akun in "${data[@]}"
    do
        port=$(cat /etc/shadowsocks-libev/akun.conf | grep '^port_tls' | cut -d ' ' -f 2 | tr '\n' ' ' | awk '{print $'"$x"'}')
        jum=$(netstat -anp | grep ESTABLISHED | grep obfs-server | cut -d ':' -f 2 | grep -w $port | awk '{print $2}' | sort | uniq | nl)
        if [[ -z "$jum" ]]; then
            echo > /dev/null
        else
            echo " $akun - $port"
            echo "$jum"
            echo "----------------------------------"
        fi
        x=$(( "$x" + 1 ))
    done
    data=( `cat /etc/shadowsocks-libev/akun.conf | grep '^###' | cut -d ' ' -f 2`)
    x=1
    echo ""
    echo "----------------------------------"
    echo " User |  No TLS"
    echo "----------------------------------"
    for akun in "${data[@]}"
    do
        port=$(cat /etc/shadowsocks-libev/akun.conf | grep '^port_http' | cut -d ' ' -f 2 | tr '\n' ' ' | awk '{print $'"$x"'}')
        jum=$(netstat -anp | grep ESTABLISHED | grep obfs-server | cut -d ':' -f 2 | grep -w $port | awk '{print $2}' | sort | uniq | nl)
        if [[ -z "$jum" ]]; then
            echo > /dev/null
        else
            echo " $akun - $port"
            echo "$jum"
            echo "----------------------------------"
        fi
        x=$(( "$x" + 1 ))
    done
}

# Start the script
menu