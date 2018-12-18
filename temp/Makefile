GCC?=aarch64-linux-gnu-gcc
EXT_GCC_OPTS?=-Wa,-mregnames
GCCOPTS?=-Wall -std=gnu99 -O0 -pthread $(EXT_GCC_OPTS)
LINKOPTS?=-static
NAME?=run
EXE=$(NAME).exe

all: $(EXE)

clean:
	/bin/rm -f *.o *.s *.t *.exe *~ $(H)

cleansource:
	/bin/rm -f *.o *.c *.h *.s *~

$(EXE): $(NAME).o
	$(GCC)  $(GCCOPTS) $(LINKOPTS) -o $@ $(NAME).o

%.o:%.c
	$(GCC) $(GCCOPTS) $(LINKOPTS) -c -o $@ $<

%.s:%.c
	$(GCC) -DASS $(GCCOPTS) -S $<

%.t:%.s
	awk -f show.awk $< > $@

%.h:%.t
	sh toh.sh $< > $@
