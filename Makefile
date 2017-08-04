.SUFFIXES : .c
 
OBJECT = main.o
SRC = main.c
 
CC = gcc
CFLAGS = -lpcap -W -Wall

TARGET = arp
 
$(TARGET) : $(OBJECT)
	@echo "------------------------------------"
	@echo [Complie] arp
	$(CC) -o $(TARGET) $(OBJECT) $(CFLAGS)
	@echo [OK] arp
	@echo "------------------------------------"
	rm -rf $(OBJECT)
 
clean :
	rm -rf $(OBJECT) $(TARGET)

new :
	@$(MAKE) -s clean
	@$(MAKE) -s

main.o : main.c net_header.h
