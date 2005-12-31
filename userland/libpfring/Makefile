CC=gcc -g

KERNEL_DIR=/home/deri/PF_RING/workspace/linux-2.4.31-1-686-smp-ring3/include/
INCLUDE=-I$(KERNEL_DIR)
TARGET=pfcount

$(TARGET): pfcount.o pfring.o
	$(CC) pfcount.o pfring.o -o $(TARGET)

pfring.o: pfring.c pfring.h
	$(CC) -c $(INCLUDE) $<

pfcount.o: pfcount.c
	$(CC) -c $(INCLUDE) $<

clean:
	/bin/rm -f $(TARGET) *.o *~
