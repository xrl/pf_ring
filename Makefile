all:
	cd kernel; make
	cd userland; make
	cd drivers; make

clean:
	cd kernel; make clean
	cd userland; make clean
	cd drivers; make clean

