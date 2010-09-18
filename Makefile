all:
	cd kernel; make
	cd userland; make

clean:
	cd kernel; make clean
	cd userland; make clean

