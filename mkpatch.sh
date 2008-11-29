#!/bin/bash

#
# Rocco Carbone <rocco@ntop.org> - 1Q 2004 GPL
# Luca Deri <deri@ntop.org>
# Allan Kerr <allan_kerr@agilent.com>
# Willy Tarreau <wtarreau@exosec.fr>

# Modified beyond reason by cpw (if not Debian, then try PREFIX=linux
# with source in /tmp, or let this script pull the kernel down.)
# otherwise it will assume you have debians kernel source pkg installed.
function I_should ()
{
  echo -n "${*}?[Yn]"; read y
  y=`echo $y | tr 'A-Z' 'a-z'`
  if test \( \( -z "$y" \) -o \( "$y" = "y" \) \) -o \( "$y" = "yes" \); then
    true
  else
    false
  fi
}

function break_link ()
{
  local file

  for file in "$@"; do
    if [ -e "$file" ]; then
      cp "$file" "$file.unlinked" && mv "$file.unlinked" "$file"
    fi
  done
}

PATCH=PF_RING
PREFIX=linux
# or
#PREFIX=kernel-source
# kernel identifiers.
VERSION=${VERSION:-2}
PATCHLEVEL=${PATCHLEVEL:-6}
SUBLEVEL=${SUBLEVEL:-24.7}
KERNEL_VERSION=$VERSION.$PATCHLEVEL.$SUBLEVEL
EXTRAVERSION=${EXTRAVERSION:--1-686-smp-$PATCH}

KERNEL=$PREFIX-$KERNEL_VERSION
MYKERNEL=$PREFIX-${KERNEL_VERSION}$EXTRAVERSION

# Where the build process will take effect.
if test $PREFIX = "linux"; then
  workspace=`pwd`
  z=z
  SOURCE=$KERNEL.tar.gz
  BUILDDIR=$workspace/workspace
  SOURCES=$workspace/workspace
else
  z=j
  SOURCE=$KERNEL.tar.bz2
  BUILDDIR=/usr/local/src
  SOURCES=/usr/src
fi
#
echo "Creating patch for Linux kernel $KERNEL ..."
echo "Edit this file (mkpatch.sh) for a different kernel version"

# Set it to "yes" if you want to keep a local copy of the original files.
saveorg=${saveorg:-yes}
# Initialize errors which could accrue as we proceed
errors=0

test -z $PWD || PWD=`pwd`

# Create the build directory.
if [ ! -d $BUILDDIR ]; then
  mkdir $BUILDDIR
  echo "Creating spool directory $BUILDDIR"
else
  echo "Kernel build area is $BUILDDIR"
  rm $BUILDDIR/$PATCH
fi

# create a link file (we might have a new definition)
ln -sf $PWD $BUILDDIR/$PATCH
echo "Creating link to $PWD in $BUILDDIR called $PATCH"

# Move to the build directory.
cd $BUILDDIR
# Download the tar file (if not yet here).
if [ ! -f $SOURCES/$SOURCE ]; then
  if [ -f $HOME/pub/$SOURCE ]; then
    SOURCES=$HOME/pub
    cp $HOME/pub/$SOURCE .
    echo "Put $SOURCES/$SOURCE in $BUILDDIR"
  elif [ -f /tmp/$SOURCE ]; then
    cp /tmp/$SOURCE .
    echo "Put $SOURCES/$SOURCE in $BUILDDIR"
  else
    echo "Unable to find local kernel source $SOURCES/$SOURCE"
    echo "Fetching kernel from the Internet... and storing in $BUILDDIR"
    echo
    SOURCES=$BUILDDIR
    wget http://www.kernel.org/pub/linux/kernel/v$VERSION.$PATCHLEVEL/$SOURCE
    if test -f $SOURCE; then
      echo "The kernel source file $SOURCE is in $SOURCES"
    else
      cat <<EOF
  
    Sorry, I could not get the kernel source from:
  
      http://www.kernel.org/pub/linux/kernel/v$VERSION.$PATCHLEVEL/$SOURCE
    
    Better luck next time.

EOF
      exit 1
    fi
  fi
else
    echo "Found $SOURCE in source directory $SOURCES"
fi
 
# Untar Linux sources (if needed).
if [ ! -d $KERNEL ]; then
  echo "Untarring Linux sources (read-only tree) in "`pwd`"/$KERNEL"
  tar ${z}xf $SOURCES/$SOURCE
  chmod -R u+w $KERNEL
else
  echo "Looks like the source is already extracted here `pwd`/$KERNEL"
fi

# Move to the linux patch directory.
extract=1
if [ ! -d $MYKERNEL ]; then
  mkdir $MYKERNEL
  extract=0
else
  if I_should "Should $MYKERNEL be re-created"; then
    rm -rf $MYKERNEL
    mkdir $MYKERNEL
    extract=0
  else
    echo "Ok, $MYKERNEL left in it's current state."
  fi
fi

if test $extract -eq 0; then
  echo "Cloning Linux sources (read-write tree) in `pwd`"
# Need to remove read-write kernel if we created it before
  rm -rf $MYKERNEL
  cp -al $KERNEL $MYKERNEL
fi

#
# Apply patches to kernel write tree.
#

cat <<EOF
Patching Linux sources ...
  1. Install additional file include/linux/ring.h with definitions
     for packet ring.
EOF
if [ ! -f $MYKERNEL/include/linux/ring.h ]; then
  cp $PATCH/kernel/include/linux/ring.h $MYKERNEL/include/linux/ring.h
  echo "     done"
else
  echo "     ring.h already installed"
fi

cat <<EOF
  2. Install the ring sources under the kernel tree.
EOF
if [ ! -d $MYKERNEL/net/ring ]; then
  echo "     Installing kernel ring sources in"
  echo -n "     $MYKERNEL/net/ring ..."
  mkdir $MYKERNEL/net/ring
  case $PATCHLEVEL in
  4|6)
   cp $PATCH/kernel/net/ring/Makefile-2.$PATCHLEVEL.X $MYKERNEL/net/ring/Makefile
   cp $PATCH/kernel/net/ring/ring_packet.c $MYKERNEL/net/ring/ring_packet.c
   echo " done";;
  *)
   echo "     PATCHLEVEL is not 4 or 6!"; exit 1;;
  esac
else
  echo "     $MYKERNEL/net/ring already installed"
fi

echo "  3. Patch net/core/dev.c ... "

if [ -f $MYKERNEL/net/core/dev.c -a ! -f $MYKERNEL/net/core/dev.c.ORG -a $saveorg = "yes" ]; then
  cp $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.ORG
fi

# Three small modifications must be made to this file
# for both for 2.4.X and 2.6.X kernel series.

# Check if the patches are already present.

if ! grep -q "#include <linux/ring.h>" $MYKERNEL/net/core/dev.c; then
  echo "     Patch #1 (define ring_handler)"
  if test -f $PATCH/kernel/net/core/PATCH-1-to-dev.c; then
    #
    # The first patch conditionally defines the static kernel variable
    # ring_handler. It is defined in the source file net/core/PATCH-1-to-dev.c
    # and it should be added as soon as possible within the file.
    # (for example immediately after latest #include <...>)
  
    line=`grep -n "#include" $MYKERNEL/net/core/dev.c|tail -n 1 | cut -d":" -f 1`
    line=`expr $line + 1`
    mv $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.tmp
    cat $MYKERNEL/net/core/dev.c.tmp | sed "$line r $PATCH/kernel/net/core/PATCH-1-to-dev.c" > $MYKERNEL/net/core/dev.c
    rm -f $MYKERNEL/net/core/dev.c.tmp
  else
    cat <<EOF

     WARNING: Patch 1, $PATCH/kernel/net/core/PATCH-1-to-dev.c not found
     Could not define ring_handler

EOF
    errors=`expr $errors + 1`
  fi

  echo "     Patch #2 (modify function netif_rx [non-NAPI])"
  # The first patch must be applied to the function "netif_rx" in order
  # to immediately return in case the packet has been copied into a ring.
  # It is defined in the source file net/core/PATCH-2-to-dev.c.
  
  if test -f $PATCH/kernel/net/core/PATCH-2-to-dev.c; then
    line=`grep -n "int netif_rx *(" $MYKERNEL/net/core/dev.c | tail -n 1 | cut -d":" -f 1`
    line=`expr $line + 5`
  
    mv $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.tmp
    cat $MYKERNEL/net/core/dev.c.tmp | sed "$line r $PATCH/kernel/net/core/PATCH-2-to-dev.c" > $MYKERNEL/net/core/dev.c
    rm -f $MYKERNEL/net/core/dev.c.tmp
  else
    cat <<EOF

     WARNING: Patch 2, $PATCH/kernel/net/core/PATCH-2-to-dev.c not found
     Could not patch netif_rx function

EOF
    errors=`expr $errors + 1`
  fi

  echo "     Patch #3 (modify netif_receive_skb [NAPI])"
  if test -f $PATCH/kernel/net/core/PATCH-3-to-dev.c; then
    #
    # This patch must be applied to the function "netif_receive_skb" in order
    # to immediately return in case the packet has been copied into a ring.
    # It is defined in the source file net/core/PATCH-3-to-dev.c.
  
    line=`grep -n "int netif_receive_skb" $MYKERNEL/net/core/dev.c | tail -n 1 | cut -d":" -f 1`
    line=`expr $line + 5`
  
    mv $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.tmp
    cat $MYKERNEL/net/core/dev.c.tmp | sed "$line r $PATCH/kernel/net/core/PATCH-3-to-dev.c" > $MYKERNEL/net/core/dev.c
    rm -f $MYKERNEL/net/core/dev.c.tmp
  else
    cat <<EOF

     WARNING: Patch 3, $PATCH/kernel/net/core/PATCH-3-to-dev.c not found
     Could not patch netif_receive_skb function

EOF
    errors=`expr $errors + 1`
  fi

  echo "     Patch #4 (modify dev_queue_xmit, found in PATCH-4-to-dev.c)"
    #
    # This patch must be applied to the function "dev_queue_xmit" in order
    # to handle the packet into a ring.
    # It is defined in the source file net/core/PATCH-4-to-dev.c.
  
  if test -f $PATCH/kernel/net/core/PATCH-4-to-dev.c; then
    line=`grep -n "if (q->enqueue) {" $MYKERNEL/net/core/dev.c | tail -n 1 | cut -d":" -f 1`
    line=`expr $line + 1`
  
    mv $MYKERNEL/net/core/dev.c $MYKERNEL/net/core/dev.c.tmp
    cat $MYKERNEL/net/core/dev.c.tmp | sed "$line r $PATCH/kernel/net/core/PATCH-4-to-dev.c" > $MYKERNEL/net/core/dev.c
    rm -f $MYKERNEL/net/core/dev.c.tmp
  
    echo "     ... done"
else
    cat <<EOF

     WARNING: Patch 3, $PATCH/kernel/net/core/PATCH-4-to-dev.c not found
     Could not patch netif_rx and netif_receive_skb functions

EOF
    errors=`expr $errors + 1`
  fi
else
  echo " dev.c already patched."
fi

# 4. Patch net/Makefile
if [ ! -f $MYKERNEL/net/Makefile.ORG -a $saveorg = "yes" ]; then
  cp $MYKERNEL/net/Makefile $MYKERNEL/net/Makefile.ORG
fi

# Check if the patch is already present.
patch=3
if ! grep -q "CONFIG_RING" $MYKERNEL/net/Makefile; then
  patch=`expr $patch + 1`
  echo -n "  ${patch}. Patching file net/Makefile ..."

  # A line to tell the make to compile under the ring directory must be added.
  case $PATCHLEVEL in
  6)
    # Look for the last module and add a new directive.
    line=`grep -n "8021q/" $MYKERNEL/net/Makefile | tail -n 1 | cut -d":" -f 1`
    mv $MYKERNEL/net/Makefile $MYKERNEL/net/Makefile.tmp
    cat $MYKERNEL/net/Makefile.tmp | sed "$line a obj-\$(CONFIG_RING)		+= ring/" > $MYKERNEL/net/Makefile
    rm -f $MYKERNEL/net/Makefile.tmp
    ;;
  4)
    # 2.4.X kernel series
    # Add the ring directory to the mod-subdirs list
    mv $MYKERNEL/net/Makefile $MYKERNEL/net/Makefile.tmp
    cat $MYKERNEL/net/Makefile.tmp | sed -e "s|mod-subdirs :=\(.*\)|mod-subdirs :=\1 ring|" > $MYKERNEL/net/Makefile
    rm -f $MYKERNEL/net/Makefile.tmp
    # Add a line to define the compilation of the ring
    # Look for the line with VLAN_8021Q (usually last networking option) and add a new directive.
    line=`grep -n "VLAN_8021Q" $MYKERNEL/net/Makefile | tail -n 1 | cut -d":" -f 1`
    mv $MYKERNEL/net/Makefile $MYKERNEL/net/Makefile.tmp
    cat $MYKERNEL/net/Makefile.tmp | sed "$line a subdir-\$(CONFIG_RING)		+= ring" > $MYKERNEL/net/Makefile
    rm -f $MYKERNEL/net/Makefile.tmp
    ;;
  *)
    echo " error"
    echo "Only versions 6 and 4 are handled by this patch kit"
    exit 1
  esac 
  echo " done"
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

  patch=`expr $patch + 1`
  echo -n "  ${patch}. Patching file include/net/sock.h ..."

  if ! grep -q "struct ring_opt.*pf_ring" $MYKERNEL/include/net/sock.h; then
    # Look for the line with af_packet and add the additional field pf_ring.
    line=`grep -n "af_packet" $MYKERNEL/include/net/sock.h | tail -n 1 | cut -d":" -f 1`
    line=`expr $line + 1`
  
    mv $MYKERNEL/include/net/sock.h $MYKERNEL/include/net/sock.h.tmp
    cat $MYKERNEL/include/net/sock.h.tmp | sed "$line r $PATCH/kernel/include/net/PATCH-to-sock.h" > $MYKERNEL/include/net/sock.h
    rm -f $MYKERNEL/include/net/sock.h.tmp
    echo " done"
  else
    echo " already patched."
  fi
  if test -f  $PATCH/kernel/net/PATCH-to-netsyms.c; then
    # 6. Patch net/netsyms.c
    patch=`expr $patch + 1`
    echo -n "  ${patch}. Patching file net/netsyms.c ..."
    if ! grep -q "linux/ring.h" $MYKERNEL/net/netsyms.c; then
      break_link $MYKERNEL/net/netsyms.c
      cat $PATCH/kernel/net/PATCH-to-netsyms.c >>  $MYKERNEL/net/netsyms.c
      echo " done"
    else
      echo " already patched".
    fi
  fi
fi

#
# Patch the kernel configuration files.
#
if [ -f $MYKERNEL/net/Config.in ]; then

  # 2.4.X kernel series

  # Patch net/Config.in

  patch=`expr $patch + 1`
  echo -n "  ${patch}. Patching file net/Config.in ..."

  if ! grep -q "source net/ring/Config.in" $MYKERNEL/net/Config.in; then
    if [ ! -f $MYKERNEL/net/Config.in.ORG -a $saveorg = "yes" ]; then
      cp $MYKERNEL/net/Config.in $MYKERNEL/net/Config.in.ORG
    fi
  
    line=`grep -n "Socket Filtering" $MYKERNEL/net/Config.in | tail -n 1 | cut -d":" -f 1`
  
    mv $MYKERNEL/net/Config.in $MYKERNEL/net/Config.in.tmp
    cat $MYKERNEL/net/Config.in.tmp | sed "$line r $PATCH/kernel/net/PATCH-to-Config.in" > $MYKERNEL/net/Config.in
    rm -f $MYKERNEL/net/Config.in.tmp
  
    echo " done"
  else
    echo " already patched."
  fi

  # Install net/ring/Config.in
  patch=`expr $patch + 1`
  echo "  ${patch}. Copy net/ring/Config.in to $MYKERNEL/net/ring/Config.in"
  cp $PATCH/kernel/net/ring/Config.in $MYKERNEL/net/ring/Config.in

else

  # 2.6.X kernel series
  patch=`expr $patch + 1`
  echo -n "  ${patch}. Copy net/ring/Kconfig to $MYKERNEL/net/ring/Kconfig"
  # Install net/ring/Kconfig
  cp $PATCH/kernel/net/ring/Kconfig $MYKERNEL/net/ring/Kconfig
  echo " done"

fi

if [ -f $MYKERNEL/net/Kconfig ]; then

  # 2.6.X kernel series

  # Check if the patch is already present.

    patch=`expr $patch + 1`
    echo -n "  ${patch}. Patching file net/Kconfig ..."

  if ! grep -q "net/ring/Kconfig" $MYKERNEL/net/Kconfig; then
    # Insert a new configuration directive.
#    line=`grep -n "config NET_KEY" $MYKERNEL/net/Kconfig | tail -n 1 | cut -d":" -f 1`
    line=`grep -n "config INET" $MYKERNEL/net/Kconfig | tail -n 1 | cut -d":" -f 1`
    line=`expr $line - 1`

    mv $MYKERNEL/net/Kconfig $MYKERNEL/net/Kconfig.tmp
    cat $MYKERNEL/net/Kconfig.tmp | sed "$line a source \"net/ring/Kconfig\"" > $MYKERNEL/net/Kconfig
    rm -f $MYKERNEL/net/Kconfig.tmp

    cp $PATCH/kernel/net/ring/Kconfig $MYKERNEL/net/ring/Kconfig
    echo " done"
  else
    echo " already patched"
  fi

fi
cd $BUILDDIR
if test $errors -eq 0; then
  if test -d $MYKERNEL/$KERNEL; then rmdir $MYKERNEL/$KERNEL; fi
  echo "diff --unified --recursive --new-file $KERNEL $MYKERNEL > $MYKERNEL.patch"
  echo -n "Making Linux patch file. This could take some time, please wait ..."
  diff --unified --recursive --new-file $KERNEL $MYKERNEL > $MYKERNEL.patch
  rm -f $MYKERNEL.patch.gz
  gzip -9 $MYKERNEL.patch
  echo " done"
  echo "Your patch file is now in `pwd`/$MYKERNEL.patch.gz"
  exit 0
else
  echo You probably want to fix the errors indicated before getting a beer.
  exit 1
fi
#echo "DEBUG: how did we do, so far ...";exit 1
