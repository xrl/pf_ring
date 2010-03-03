#!/bin/sh


pow2()
{
    if [ $1 -eq 0 ];
    then
	mask=1
    else
	iters=$1
	mask=2
	while [ $iters -gt 1 ]
	do
	    mask=`expr $mask \* 2`
	    iters=`expr $iters - 1`
	done;
    fi
}


if [ $# -eq 0 ]; then
    echo "usage: msixbind.sh INTERFACE [SKIP CPUs] [1st CPU]"
    exit 1;
fi

eth=$1
skip=1
start=0
shift
if [ $# != 0 ]; then
    skip=$1
    shift
fi
if [ $# != 0 ]; then
    start=$1
    shift
fi

echo "Binding interface $eth"
pid=`pgrep irqbalance`
    if [ $? -eq 0 ];
    then
	echo "irqbalance is running! Pid = $pid"
	echo "it will undo anything done by this script"
	echo "Please kill it and re-run this script"
	exit
    fi

done=0
i=$start
slice=0
num_slices=`grep "${eth}:slice" /proc/interrupts | wc -l`
while [ $done != 1 ]
do
    irq_data=`grep "${eth}:slice-${slice}" /proc/interrupts`
    if [ $? != 0 ];
    then
	if [ $i != $start ];
	then
	    exit
	fi
	irq_data=`grep "${eth}" /proc/interrupts`
	if [ $? != 0 ];
	then
	    exit
	fi
    fi
    irq=`echo $irq_data |  awk '{print $1 ; }' | sed -e 's/://g'`
    pow2 $i
    file="/proc/irq/${irq}/smp_affinity"
    printf "Binding slice %2d to CPU %2d: writing mask 0x%08x to $file\n" $slice $i $mask
    printf "%x" $mask > $file
    i=`expr $i + $skip`
    slice=`expr $slice + 1`
    if [ $slice -eq $num_slices ];
    then
	exit
    fi
done
    

