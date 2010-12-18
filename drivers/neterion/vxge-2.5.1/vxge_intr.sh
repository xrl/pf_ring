time_2_wait=$1

if [ "$time_2_wait" == "" ] ; then
	echo " Please enter time to wait value. Usage: vxge_intr.sh time_to_wait count"
	exit 1
fi
count=$2

if [ "$count" == "" ] ; then
	echo " Please enter count value. Usage: vxge_intr.sh time_to_wait count"
	exit 1
fi
total_cpu=`cat /proc/cpuinfo | grep processor | tail -1 | awk '{ print $3 }'`
total_cpu=`expr $total_cpu + 1`
echo 'cpu count =' $total_cpu
echo 'time_2_wait=' $time_2_wait

while [ $count -ne 0 ]; do

cat /proc/interrupts | grep vxge > tmp
vect_cnt=0
declare msix_vects_before[35]
declare msix_vectors_after[35]

while read row ; do
	cpu=1
	j=2
	total=0
	while [ $cpu -le $total_cpu ]; do
		val=$(echo $row | gawk '{ print $'$j' }')
		total=`expr $total + $val`
		cpu=`expr $cpu + 1`
		j=`expr $j + 1`
	done
	msix_vects_before[$vect_cnt]=$total
	vect_cnt=`expr $vect_cnt + 1`
done < tmp

sleep $time_2_wait

vect_cnt=0
cat /proc/interrupts | grep vxge > tmp
while read row ; do
	cpu=1
	j=2
	total=0
	while [ $cpu -le $total_cpu ]; do
		val=$(echo $row | gawk '{ print $'$j' }')
		total=`expr $total + $val`
		cpu=`expr $cpu + 1`
		j=`expr $j + 1`
	done
	msix_vects_after[$vect_cnt]=$total
	vect_cnt=`expr $vect_cnt + 1`
done < tmp

echo -e "\nIndividual vxge driver msix interrupt rate:"
vect_cnt=0
total=0
cat /proc/interrupts | grep vxge > tmp
while read row ; do
	msix=$(echo $row|awk '{ print $1 }')
	echo $msix  $(($((${msix_vects_after[$vect_cnt]} - ${msix_vects_before[$vect_cnt]}))/$time_2_wait))
	total=`expr $total + $((${msix_vects_after[$vect_cnt]} - ${msix_vects_before[$vect_cnt]}))`
	vect_cnt=`expr $vect_cnt + 1`
done < tmp
	echo 'Total vxge driver interrupt rate =' $(($total/$time_2_wait))
count=`expr $count - 1`
done
