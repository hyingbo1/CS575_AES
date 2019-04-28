all :	aes gen

aes :	aes.cpp
	g++ -fopenmp -o aes aes.cpp

gen :	gen.cpp
	g++ -o gen gen.cpp

clean :
	rm -f aes gen 1000000
