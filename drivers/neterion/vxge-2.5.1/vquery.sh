#!/bin/bash
ifx=$1
if [ "$ifx" == "" ] ; then
	echo "Please enter interface name, for example: vquery.sh eth2"
	exit 1
fi

report="Neterion_query.log"

echo "Neterion Support Log" > $report
which ethtool
if [[ $? -eq 0 ]]; then
	errmsg=''
	ethtool $ifx >>$report 2>/dev/null
	if [[ $? -gt 0 ]]; then
		errmsg="\nethtool does not run."
	fi
else
		errmsg="\nethtool is not in /sbin."
fi
is_neterion=`ethtool -i $ifx|grep -i 'vxge\|Neterion'`
if [[ $is_neterion == '' ]]; then
    errmsg="$errmsg\nThis script runs on Neterion products only!"
fi

if [[ $errmsg != '' ]]; then
    printf "$errmsg\n"
    exit
fi

commands[0]="ifconfig -a"
commands[1]="ethtool -i $ifx"
commands[2]="cat /proc/cpuinfo|grep model|tail -1"
commands[3]="cat /proc/cpuinfo |grep 'physical id'"
commands[4]="cat /proc/cpuinfo |grep 'MHz'|tail -1"
commands[5]="cat /proc/cpuinfo |grep 'core id'"
commands[6]="cat /proc/cpuinfo |grep 'processor'"
commands[7]="uname -a"
commands[8]="cat /proc/meminfo |grep Mem"
commands[9]="print_intr"
commands[10]="print_intr_rate"
commands[11]="lspci -t -v"
commands[12]="lspci -v -xxx"
commands[13]="/sbin/sysctl -a| grep wmem "
commands[14]="sysctl -a| grep net.ipv4.tcp_timestamps "
commands[15]="sysctl -a| grep net.ipv4.tcp_sack "
commands[16]="sysctl -a| grep net.ipv4.tcp_rmem "
commands[17]="sysctl -a| grep net.ipv4.tcp_wmem "
commands[18]="sysctl -a| grep net.ipv4.tcp_mem "
commands[19]="sysctl -a| grep net.core.rmem_max "
commands[20]="sysctl -a| grep net.core.wmem_max "
commands[21]="sysctl -a| grep net.core.rmem_default "
commands[22]="sysctl -a| grep net.core.wmem_default "
commands[23]="sysctl -a| grep net.core.optmem_max "
commands[24]="sysctl -a| grep net.core.netdev_max_backlog "
commands[25]="ethtool -S $ifx"
commands[26]="ethtool -k $ifx"
commands[27]="ethtool -d $ifx"
commands[28]="netstat -s"
commands[29]="netstat -i"
commands[30]="print_vmstat"
commands[31]="cat /var/log/messages"

ver=`uname -r`
case $ver in
	2.4.*)
		ver='2.4' ;;
	*)
		ver='' ;;
esac

print_vmstat (){
	if [[ $ver = '2.4' ]]; then
		vmstat
	else
		vmstat -s
	fi
}

print_intr (){
    cat /proc/interrupts|grep -i 'xge\|Neterion'
    sleep 5
    echo
    echo "5 seconds later"
    echo
    cat /proc/interrupts|grep -i 'xge\|Neterion'
}

print_intr_rate (){
    sh vxge_intr.sh 5 5
    sleep 2
    echo
}

echo "Generating Neterion Support Log file Neterion_query.log.gz  ......."
for comm in "${commands[@]}"; do
        echo "=====================================================" >> $report
        echo "$comm" >> $report
        eval "$comm" >> $report 2>/dev/null
done

if [[ -s $report.gz ]]; then
        rm -f $report.gz
fi
gzip $report
echo "done."
