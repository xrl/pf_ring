#!/bin/sh

#
# Rocco Carbone <rocco@ntop.org> - 1Q 2004 GPL
#

# kernel identifiers.
VERSION=2
PATCHLEVEL=6
SUBLEVEL=5
EXTRAVERSION=ring

# Where the build process will take effect.
BUILDDIR=./PF_RING

KERNEL=linux-$VERSION.$PATCHLEVEL.$SUBLEVEL
MYKERNEL=linux-$VERSION.$PATCHLEVEL.$SUBLEVEL-$EXTRAVERSION
SOURCES=$KERNEL.tar.gz

#
#
#
echo "Creating patch for Linux kernel $KERNEL ..."
echo "Edit this file (mkpatch.sh) for a different kernel version"

# Set it to "yes" if you want to keep a local copy of the original files.
saveorg=yes

#
test -z $PWD || PWD=`pwd`
RINGDIR=`dirname $PWD`

# Create the build directory.
if [ ! -d $BUILDDIR ]; then
  mkdir $BUILDDIR
  echo "Creating spool directory $BUILDDIR"
fi

# create a link file
if [ ! -h $BUILDDIR/ring ]; then
  ln -sf $RINGDIR/ring $BUILDDIR/ring
fi

# Move to the build directory.
cd $BUILDDIR

# Download the tar file (if not yet here).
if [ ! -f $SOURCES ]; then
  # Check if a local copy is available; otherwise download from the Internet
  if [ -f $HOME/pub/$SOURCES ]; then
    cp $HOME/pub/$SOURCES .
    echo "Found $HOME/pub/$SOURCES ..."
  elif [ -f /tmp/$SOURCES ]; then
    cp /tmp/$SOURCES .
    echo "Found /tmp/$SOURCES ..."
  else
    echo "Unable to find local kernel source into $HOME/pub/$SOURCES:/tmp/$SOURCES"
    echo "Fetching kernel from the Internet..."
    echo
    wget http://www.kernel.org/pub/linux/kernel/v$VERSION.$PATCHLEVEL/$SOURCES
  fi
else
    echo "Using source directory $SOURCES"
fi

# Untar Linux sources (if needed).
if [ ! -d $KERNEL ]; then
  echo "Untarring Linux sources (read-only tree) in `pwd`/$KERNEL"
  tar xfz $SOURCES
fi

# Move to the linux patch directory.
if [ ! -d $MYKERNEL ]; then
  mkdir $MYKERNEL
fi
cd $MYKERNEL

# Untar Linux sources (if needed).
if [ ! -d $KERNEL ]; then
  echo "Untarring Linux sources (read-write tree) in `pwd`"
  tar xfz ../$SOURCES
  mv $KERNEL/* .
fi
cd ..


#
# Apply patches to kernel write tree.
#

echo "Patching Linux sources ..."

# 1. Install additional file include/linux/ring.h with definitions for packet ring.

if [ ! -f $MYKERNEL/include/linux/ring.h ]; then
  cp ring/kernel/include/linux/ring.h $MYKERNEL/include/linux/ring.h
  echo "Installed file $MYKERNEL/include/linux/ring.h"
fi

# 2. Install the ring sources under the kernel tree.

if [ ! -d $MYKERNEL/net/ring ]; then
  echo -n "Installing kernel ring sources in $MYKERNEL/net/ring ..."
  mkdir $MYKERNEL/net/ring
  if [ $PATCHLEVEL = "4" ]; then
    cp ring/kernel/net/ring/Makefile $MYKERNEL/net/ring/Makefile
  else
    cp ring/kernel/net/ring/Makefile-2.6.X $MYKERNEL/net/ring/Makefile
  fi
  cp ring/kernel/net/ring/ring_packet.c $MYKERNEL/net/ring/ring_packet.c

  echo " done."
fi


# 3. Patch net/core/dev.c

if [ ! -f $MYKERNEL/net/core/dev.c.ORG -a $saveorg = "yes" ]; then
  cp $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.ORG
fi

# Three small modifications must be made to this file
# for both for 2.4.X and 2.6.X kernel series.

# Check if the patches are already present.

if ! grep -q "#include <linux/ring.h>" $MYKERNEL/net/core/dev.c; then

  echo -n "Patching file net/core/dev.c ..."

  #
  # Patch #1
  #
  # The first patch conditionally defines the static kernel variable ring_handler.
  # It is defined in the source file net/core/PATCH-1-to-dev.c and it should be
  # added as soon as possible within the file
  # (for example immediately after latest #include <...>)

  line=`grep -n "#include" $MYKERNEL/net/core/dev.c | tail -1 | cut -d":" -f 1`
  line=`expr $line + 1`

  mv $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.tmp
  cat $MYKERNEL/net/core/dev.c.tmp | sed "$line r ring/kernel/net/core/PATCH-1-to-dev.c" > $MYKERNEL/net/core/dev.c
  rm -f $MYKERNEL/net/core/dev.c.tmp

  #
  # Patch #2
  #
  # This patch must be applied to the function "netif_rx" in order
  # to immediately return in case the packet has been copied into a ring.
  # It is defined in the source file net/core/PATCH-2-to-dev.c.

  line=`grep -n "int netif_rx" $MYKERNEL/net/core/dev.c | tail -1 | cut -d":" -f 1`
  line=`expr $line + 5`

  mv $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.tmp
  cat $MYKERNEL/net/core/dev.c.tmp | sed "$line r ring/kernel/net/core/PATCH-2-to-dev.c" > $MYKERNEL/net/core/dev.c
  rm -f $MYKERNEL/net/core/dev.c.tmp

  #
  # Patch #3
  #
  # This patch must be applied to the function "netif_receive_skb" in order
  # to immediately return in case the packet has been copied into a ring.
  # It is defined in the source file net/core/PATCH-2-to-dev.c.

  line=`grep -n "int netif_receive_skb" $MYKERNEL/net/core/dev.c | tail -1 | cut -d":" -f 1`
  line=`expr $line + 5`

  mv $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.tmp
  cat $MYKERNEL/net/core/dev.c.tmp | sed "$line r ring/kernel/net/core/PATCH-2-to-dev.c" > $MYKERNEL/net/core/dev.c
  rm -f $MYKERNEL/net/core/dev.c.tmp

  #
  # Patch #4
  #
  # This patch must be applied to the function "dev_queue_xmit" in order
  # to handle the packet into a ring.
  # It is defined in the source file net/core/PATCH-3-to-dev.c.

  line=`grep -n "Grab device queue" $MYKERNEL/net/core/dev.c | tail -1 | cut -d":" -f 1`
  line=`expr $line - 1`

  mv $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.tmp
  cat $MYKERNEL/net/core/dev.c.tmp | sed "$line r ring/kernel/net/core/PATCH-3-to-dev.c" > $MYKERNEL/net/core/dev.c
  rm -f $MYKERNEL/net/core/dev.c.tmp

  echo " done."
fi


# 4. Patch net/Makefile
if [ ! -f $MYKERNEL/net/Makefile.ORG -a $saveorg = "yes" ]; then
  cp $MYKERNEL/net/Makefile $MYKERNEL/net/Makefile.ORG
fi

# Check if the patch is already present.

if ! grep -q "ring" $MYKERNEL/net/Makefile; then

  echo -n "Patching file net/Makefile ..."

  # A line to tell the make to compile under the ring directory must be added.
  if [ $PATCHLEVEL = "6" ]; then

    # Look for the last module and add a new directive.
    line=`grep -n "8021q/" $MYKERNEL/net/Makefile | tail -1 | cut -d":" -f 1`

    mv $MYKERNEL/net/Makefile $MYKERNEL/net/Makefile.tmp
    cat $MYKERNEL/net/Makefile.tmp | sed "$line a obj-\$(CONFIG_RING)		+= ring/" > $MYKERNEL/net/Makefile
    rm -f $MYKERNEL/net/Makefile.tmp

  else

    # 2.4.X kernel series

    # Add the ring directory to the mod-subdirs list

    mv $MYKERNEL/net/Makefile $MYKERNEL/net/Makefile.tmp
    cat $MYKERNEL/net/Makefile.tmp | sed -e "s|mod-subdirs :=\(.*\)|mod-subdirs :=\1 ring|" > $MYKERNEL/net/Makefile
    rm -f $MYKERNEL/net/Makefile.tmp

    # Add a line to define the compilation of the ring

    # Look for the line with VLAN_8021Q (usually last networking option) and add a new directive.
    line=`grep -n "VLAN_8021Q" $MYKERNEL/net/Makefile | tail -1 | cut -d":" -f 1`

    mv $MYKERNEL/net/Makefile $MYKERNEL/net/Makefile.tmp
    cat $MYKERNEL/net/Makefile.tmp | sed "$line a subdir-\$(CONFIG_RING)		+= ring" > $MYKERNEL/net/Makefile
    rm -f $MYKERNEL/net/Makefile.tmp

  fi

  echo " done."
fi


# Add patches valid only for the 2.4.X kernel series.

if [ $PATCHLEVEL = "4" ]; then

  # 5. Patch include/net/sock.h

  # Luca added the field "struct ring_opt *pf_ring" to the "union protinfo"
  # which in turn is a field of "struct sock". This is only valid for
  # Linux kernel version 2.4.X; starting at version kernel 2.6.X
  # there is no need to patch this file because "protinfo" was made just
  # a void pointer, as the protocol specific parts were moved to respective
  # headers and ipv4/v6, etc now use private slabcaches for its socks.

  if [ ! -f $MYKERNEL/include/net/sock.h.ORG -a $saveorg = "yes" ]; then
    cp $MYKERNEL/include/net/sock.h $MYKERNEL/include/net/sock.h.ORG
  fi

  echo -n "Patching file include/net/sock.h ..."

  # Look for the line with af_packet and add the additional field pf_ring.
  line=`grep -n "af_packet" $MYKERNEL/include/net/sock.h | tail -1 | cut -d":" -f 1`
  line=`expr $line + 1`

  mv $MYKERNEL/include/net/sock.h $MYKERNEL/include/net/sock.h.tmp
  cat $MYKERNEL/include/net/sock.h.tmp | sed "$line r ring/kernel/include/net/PATCH-to-sock.h" > $MYKERNEL/include/net/sock.h
  rm -f $MYKERNEL/include/net/sock.h.tmp

  echo " done."

  # 6. Patch net/netsyms.c
  echo -n "Patching file net/netsyms.c ..."
  cat ring/kernel/net/PATCH-to-netsyms.c >>  $MYKERNEL/net/netsyms.c
  echo " done."

fi


#
# Patch the kernel configuration files.
#
if [ -f $MYKERNEL/net/Config.in ]; then

  # 2.4.X kernel series

  # Patch net/Config.in

  echo -n "Patching file net/Config.in ..."

  if [ ! -f $MYKERNEL/net/Config.in.ORG -a $saveorg = "yes" ]; then
    cp $MYKERNEL/net/Config.in $MYKERNEL/net/Config.in.ORG
  fi

  line=`grep -n "Socket Filtering" $MYKERNEL/net/Config.in | tail -1 | cut -d":" -f 1`

  mv $MYKERNEL/net/Config.in $MYKERNEL/net/Config.in.tmp
  cat $MYKERNEL/net/Config.in.tmp | sed "$line r ring/kernel/net/PATCH-to-Config.in" > $MYKERNEL/net/Config.in
  rm -f $MYKERNEL/net/Config.in.tmp

  echo " done."

  # Install net/ring/Config.in
  cp ring/kernel/net/ring/Config.in $MYKERNEL/net/ring/Config.in
  echo "Installed file $MYKERNEL/net/ring/Config.in"

else

  # 2.6.X kernel series

  # Install net/ring/Kconfig
  cp ring/kernel/net/ring/Kconfig $MYKERNEL/net/ring/Kconfig

fi


if [ -f $MYKERNEL/net/Kconfig ]; then

  # 2.6.X kernel series

  # Check if the patch is already present.

  if ! grep -q "net/ring" $MYKERNEL/net/Kconfig; then

    echo -n "Patching file net/Kconfig ..."

    # Insert a new configuration directive.
    line=`grep -n "config NET_KEY" $MYKERNEL/net/Kconfig | tail -1 | cut -d":" -f 1`
    line=`expr $line - 1`

    mv $MYKERNEL/net/Kconfig $MYKERNEL/net/Kconfig.tmp
    cat $MYKERNEL/net/Kconfig.tmp | sed "$line a source \"net/ring/Kconfig\"" > $MYKERNEL/net/Kconfig
    rm -f $MYKERNEL/net/Kconfig.tmp

    cp ring/kernel/net/ring/Kconfig $MYKERNEL/net/ring/Kconfig
    echo " done."
  fi

fi

echo -n "Making Linux patch file. Please wait ..."

rmdir $MYKERNEL/$KERNEL
diff --unified --recursive --new-file $KERNEL $MYKERNEL > $MYKERNEL.patch
rm -f $MYKERNEL.patch.gz
gzip -9 $MYKERNEL.patch
mkdir $MYKERNEL/$KERNEL
echo " done."

echo "Your patch file is now in `pwd`/$MYKERNEL.patch.gz"

exit 0


