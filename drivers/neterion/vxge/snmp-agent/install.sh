PREFIX=$1
MIBDIR=$PREFIX/usr/share/snmp/mibs
echo "Installing Neterion mib files to $MIBDIR"
install -v -m 666 -d $MIBDIR
if [ -f NETERION-MIB.txt ] && [ -f NETERION-VXGE-MIB.txt ]; then
{
	install -v -m 666 NETERION-MIB.txt $MIBDIR
	install -v -m 666 NETERION-VXGE-MIB.txt $MIBDIR
}
else
{
	install -v -m 666 ../mibs/NETERION-MIB.txt $MIBDIR
	install -v -m 666 ../mibs/NETERION-VXGE-MIB.txt $MIBDIR
}
fi

echo "Installing vxge net-snmp agent module to $PREFIX/usr/local/vxge/"
install -v -m 666 -d $PREFIX/usr/local/vxge/
install -v -m 777 vxge.so $PREFIX/usr/local/vxge/

