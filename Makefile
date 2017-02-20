GXX:= g++
FLAGS:= -g
all: test

test: l.a blob.o eg.o sm.o algs.o test.o generators.o
	$(GXX) $(FLAGS) -o test blob.o eg.o sm.o algs.o test.o generators.o l.a

blob.o: blob.cpp
	$(GXX) $(FLAGS) -c blob.cpp

test.o: test.cpp
	$(GXX) $(FLAGS) -c test.cpp

algs.o: algs.cpp
	$(GXX) $(FLAGS) -c algs.cpp

eg.o: eg.cpp
	$(GXX) $(FLAGS) -c eg.cpp

sm.o: sm.cpp
	$(GXX) $(FLAGS) -c sm.cpp

generators.o: generators.c
	$(GXX) $(FLAGS) -c generators.c

clear:
	rm -f *.o test
