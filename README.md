#How to run it
1. type command "make all" to compile all files.
2. type command "./gen 1000000" to generate a test data and its volume is 1000000 Byte.
3. type command "time ./aes 1000000 -e 0 -p 4" to test the basic function

#Here I will explain the argument in the command above
1. first argument "time" means to compute the time used by executing program
2. second argument "./aes" means executing program
3. third argument "1000000" means that the file name of object will be encrypted.
4. 4th argument "-e" means that this command will encrypt the file. Additionally, the 4th argument can be "-d" which means decrypt the file.
5. 5th argument "0" means that here will use a key 128 bit long. And we also can choose "1" or "2" ,here,  which represent a key 192 bit long or 256 bit long. But we only can change the key in file "aes.cpp".
6. 6th argument "-p" means that here will execute program in  parallel. And "-s" means execute program in sequencial version.
7. 7th argument "4" means the core will be used in executing. But it only avalible in parallel condition which means 6th argument should be "-p"

#How to compare different running time between sequential version and parallel versions.
1. type command "time ./aes 1000000 -e 0 -s" to run sequential version. 
2. type command "time ./aes 1000000 -e 0 -p 2" to run parallel version with 2 threads.
3. type command "time ./aes 1000000 -e 0 -p 4" to run parallel version with 4 threads.
4. type command "time ./aes 1000000 -e 0 -p 8" to run parallel version with 8 threads.
5. At last, we can observe the result that the more threads we use the running time is shorter.

#How to verify the rightness of this program
1. we can use a website "http://aes.online-domain-tools.com" to verify it.
2. just upload the file which name is 1000000 to that website. set key as "0123456789012345"(because I initial the key in aes.cpp ). Then it will show the data encrypted in hex.
3. type command "hexdump encryption_parallel_file". Then we can compare the result with the result from website.
