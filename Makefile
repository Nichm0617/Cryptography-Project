both : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp client.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D NDEBUG -D NRSA -D ATM -o atm.out -lgmp -lm \
	&& g++ KeyGeneration.cpp KeyEncryption.cpp bank.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D NDEBUG -D NRSA -D BANK -o bank.out -lgmp -lm \
	&& echo Hey, it compiles!

hello : hello.cpp
	g++ hello.cpp -D NDEBUG

atm : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp client.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D NDEBUG -D ATM -o atm.out -lgmp -lm
#I inserted the one below
my_atm : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp MY_client.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D NDEBUG -D NRSA -D ATM -o my_atm.out -lgmp -lm		

bank : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp bank.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D NDEBUG -D BANK -o bank.out -lgmp -lm

testatm : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp client.cpp aes/**.cpp RSA/**.cpp \
			ssh.cpp hmac/**.cpp util.cpp -D NDEBUG -D ATM -o atm.out -lgmp -lm -g

testbank : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp bank.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D BANK -o bank.out -lgmp -lm -g

rawatm : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp client.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D BANK -D NENCRYPT=1 -o atm.out -lgmp -lm -g

rawbank : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp bank.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D BANK -D NENCRYPT=1 -o bank.out -lgmp -lm -g

dhatm : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp client.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D BANK -D NRSA=1 -o atm.out -lgmp -lm -g

dhbank : **.[ch]pp **/**.[ch]pp **/**.h
	g++ KeyGeneration.cpp KeyEncryption.cpp bank.cpp aes/**.cpp RSA/**.cpp \
		ssh.cpp hmac/**.cpp util.cpp -D BANK -D NRSA=1 -o bank.out -lgmp -lm -g

mkkeys : MakeKeys.cpp RSA/RSA.cpp RSA/RSA.h util.[ch]pp
	g++ MakeKeys.cpp RSA/RSA.cpp util.cpp -o MakeKeys.out -lgmp
