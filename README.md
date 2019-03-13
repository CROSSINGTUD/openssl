Fork of OQS-OpenSSL\_1\_1\_1-stable
==========================

**OpenSSL** ([https://openssl.org/](https://openssl.org/)) is an open-source TLS/SSL and crypto library.  (View the original [README file](https://github.com/CROSSINGTUD/openssl/README) for OpenSSL.)

This branch is a fork of the OQS-OpenSSL\_1\_1\_1-stable branch of the **Open Quantum Safe (OQS) project** which adds the following:

-  backwards compatible hybrid certificates
-  combining two keys into one hybrid key
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.

More information on OQS can be found on the website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms. OpenSSL can use either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs; Our fork uses the master branch, because we have to use post-quantum authentication for the hybrid certificates.

**OQS-OpenSSL\_1\_1\_1-stable** is an integration of liboqs into (a fork of) OpenSSL 1.1.1.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography in the TLS 1.3 protocol.  The integration should not be considered "production quality".
See more about the OQS branch at [OQS-OpenSSL\_1\_1\_1-stable branch](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable)


Contents of branch OQS-OpenSSL\_1\_1\_1-stable
----------------------------------------------
This fork integrates backwards compatible hybrid certificates in the existing OQS-OpenSSL\_1\_1\_1-stable branch. The certificates consist of a post-quantum safe signature and a non-post-quantum safe signature. See the technical documentation for more details about the design and implementation. This forks also adds the ability to combine two seperate keys into one hybrid key which can then be used for hybrid authentication. 

### Key exchange mechanisms

The following key exchange / key encapsulation mechanisms from liboqs are supported (assuming they have been enabled in liboqs):

- `oqs_kem_default`: this special mechanisms uses the liboqs's default configured scheme. This is useful to test schemes not yet directly supported by OpenSSL.
- `bike1l1`, `bike1l3`, `bike1l5`, `bike2l1`, `bike2l3`, `bike2l5`, `bike3l1`, `bike3l3`, `bike3l5` (not currently on Windows)
- `frodo640aes`, `frodo640cshake`, `frodo976aes`, `frodo976cshake`
- `newhope512cca`, `newhope1024cca`
- `sidh503`, `sidh751`
- `sike503`, `sike751`


### Authentication mechanisms

The following signature schemes from liboqs are supported (assuming they have been enabled in liboqs):

- `picnicL1FS`
- `qteslaI`, `qteslaIIIsize`, `qteslaIIIspeed` (not currently on Windows)

The following hybrid schemes are supported, using either the NIST P-256 curve or 3072-bit RSA for L1 schemes, or the NIST P-384 curve for L3 schemes:

- `p256_picnicL1FS`, `rsa3072_picnicL1FS`
- `p256_qteslaI`, `rsa3072_qteslaI`, `p384_qteslaIIIsize`, `p384_qteslaIIIspeed` (not currently on Windows)


Building on Linux 
---------------------------

Builds have been tested manually on Ubuntu 16.04 (gcc-5)

### Step 0: Install dependencies

For **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake gcc libtool libssl-dev make unzip xsltproc


### Step 1: Download fork of OpenSSL

Clone or download the source from Github:

	git clone https://github.com/CROSSINGTUD/openssl.git

### Step 2: Build liboqs

The following instructions will download and build liboqs, then install it into a subdirectory inside the OpenSSL folder.

	git clone --branch master https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=<path-to-openssl-dir>/oqs --enable-shared=no --enable-openssl --with-openssl-dir=<path-to-system-openssl-dir>
	make -j
	make install

On **Ubuntu**, `<path-to-system-openssl-dir>` can be determined by using the following command: `openssl version -d`   


### Step 3: Build fork of OpenSSL

Now we follow the standard instructions for building OpenSSL.

For **Ubuntu**:

    cd <path-to-openssl-dir>
	./Configure no-shared linux-x86_64 -lm
	make -j


The OQS fork of OpenSSL can also be built with shared libraries, but we have used `no-shared` in the instructions above to avoid having to get the shared libraries in the right place for the runtime linker.



See the [liboqs documentation](https://github.com/open-quantum-safe/liboqs/) for information on test programs in liboqs.

Creating a certificate chain
---------------------------

In practice certificate chains are used e.g. to authenticate a server or client. In the following a certificate chain of three hybrid certificates is created to show how to use the implementation.
The used config files can be found in the configs and the configs/intermediate folder.
For the post-quantum safe signature scheme we used qTeslaI and for the non-post-quantum safe scheme RSA with 3072 bits. The used signature schemes can be replaced by any of the schemes listed above. 


### Create folders for the root ca

    mkdir root_ca
    cd root_ca
    mkdir certs crl newcerts private public 
    touch index.txt
    echo 1000 > serial

The config file from the configs folder has to be copied to the created root_ca folder.

### Create folders for the intermediate ca

    cd /path-to-root_ca/root_ca
    mkdir intermediate
    cd intermediate
    mkdir certs crl csr newcerts private public
    touch index.txt
    echo 1000 > serial

The config file from configs/intermediate folder has to be copied to the created intermediate folder.

### Preparing the config files

Before creating the certificates the config files have to be adapted depending on your folder structure.
First you have to set the dir variable, which determines where the certificates, csr etc are kept. 
In the root config file set dir = /path-to-root_ca/root_ca
In the intermediate config file set dir = /path-to-root_ca/root_ca/intermediate
Then you have to set the hybridSig extension. It sets the path to the private key, which is used to create the post-quantum safe signature.
For the root config set hybridSig=file:path-to-root_ca/root_ca/private/ca.qteslakey.pem in the extension sections.
For the intermediate config set hybridSig=file:path-to-root_ca/root_ca/intermediate/private/ca.qteslakey.pem in the extension sections.
The extension sections can be adapted as in standard openssl according to your needs. For the TLS demo extendedKeyUsage = serverAuth is needed for the server.


### Creating the root certificate
    cd path-to-root_ca/root_ca
1. Create the non-post-quantum safe keypair:

    `<path-to-openssl-dir>/apps/openssl req -x509 -new -newkey rsa:3072 -pubkey -keyout private/ca.rsakey.pem -out public/ca.rsakey.pem -nodes -config openssl.cnf -noout`
    
2. Create the post-quantum safe keypair:

    `<path-to-openssl-dir>/apps/openssl req -x509 -new -newkey qteslaI -pubkey -keyout private/ca.qteslakey.pem -out public/ca.qteslakey.pem -nodes -config openssl.cnf -noout`
    
3. Create the self-signed root certificate:

    `<path-to-openssl-dir>/apps/openssl req -x509 -new -newkey rsa:3072 -pubkey -keyout private/ca.rsakey.pem -out public/ca.rsakey.pem -nodes -config openssl.cnf -noout`

### Create and verify the intermediate CA certificate

1. Create the non-post-quantum safe keypair:

    <path-to-openssl-dir>/apps/openssl req -x509 -new -newkey rsa:3072 -pubkey -keyout intermediate/private/intermediate.rsakey.pem -out intermediate/public/intermediate.rsakey.pem -nodes -config intermediate/openssl.cnf -noout
    
2. Create the post-quantum safe keypair:

    `<path-to-openssl-dir>/apps/openssl req -x509 -new -newkey qteslaI -pubkey -keyout intermediate/private/intermediate.qteslakey.pem -out intermediate/public/intermediate.qteslakey.pem -nodes -config intermediate/openssl.cnf -noout`
    
3. Creating the CSR for the intermediate CA:
When creating the CSR we have to specify the path to the post-quantum public key, which will be included as extension.

    `<path-to-openssl-dir>/apps/openssl req -config intermediate/openssl.cnf -new -key intermediate/private/intermediate.rsakey.pem -out intermediate/csr/intermediate.csr.pem -addext "hybridKey=file:path-to-root_ca/root_ca/intermediate/public/intermediate.qteslakey.pem"`

4. Create the certificate for the intermediate CA as root CA:

    `<path-to-openssl-dir>/apps/openssl ca -config openssl.cnf -extensions v3_intermediate_ca -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem`
    
5. Verify the intermediate CA certificate:

    `<path-to-openssl-dir>/apps/openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem`
    
### Create the chain file

    `cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem`
    
### Create and verify the server certificate

1. Create the non-post-quantum safe keypair:

    `<path-to-openssl-dir>/apps/openssl req -x509 -new -newkey rsa:3072 -pubkey -keyout intermediate/private/www.example.com.rsakey.pem -out intermediate/public/www.example.com.rsakey.pem -nodes -config intermediate/openssl.cnf -noout`
    
2. Create the post-quantum safe keypair:

    `<path-to-openssl-dir>/apps/openssl req -x509 -new -newkey qteslaI -pubkey -keyout intermediate/private/www.example.com.qteslakey.pem -out intermediate/public/www.example.com.qteslakey.pem -nodes -config intermediate/openssl.cnf -noout`
    
3. Creating the CSR for the server certificate:
When creating the CSR we have to specify the path to the post-quantum public key, which will be included as extension.

    `<path-to-openssl-dir>/apps/openssl req -config intermediate/openssl.cnf -new -key intermediate/private/www.example.com.rsakey.pem -out intermediate/csr/www.example.com.csr.pem -addext "hybridKey=file:/home/tobias/crossing/configs/intermediate/public/www.example.com.qteslakey.pem"`

4. Create the certificate for the server as intermediate CA:

    `<path-to-openssl-dir>/apps/openssl ca -config intermediate/openssl.cnf -extensions usr_cert -in intermediate/csr/www.example.com.csr.pem -out intermediate/certs/www.example.com.cert.pem`
    
5. Verify the server certificate:

    `<path-to-openssl-dir>/apps/openssl verify -CAfile certs/ca.cert.pem -untrusted intermediate/certs/intermediate.cert.pem intermediate/certs/www.example.com.cert.pem`
    

### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.



	apps/openssl s_server -cert intermediate/certs/www.example.com.cert.pem -key -key intermediate/private/www.example.com.rsakey.pem -www -tls1_3

In another terminal window, you can run a TLS client requesting one of the supported ciphersuites (`<KEXALG>` = one of the key exchange mechanisms listed above) or the hybrid ciphersuites (`p256-<KEXALG>`, only the NIST p256 curve in combination with L1 PQC KEM schemes are supported for now):

	apps/openssl s_client -curves <KEXALG> -CAfile intermediate/certs/ca-chain.cert.pem  -connect localhost:4433


License
-------

All modifications in the CROSSINGTUD/openssl repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](https://github.com/CROSSINGTUD/openssl/LICENSE).


### Contributors

Contributors to this fork of the open-quantum-safe/openssl branch OQS-OpenSSL\_1\_1\_1-stable include:

- Luca Gladiator (TU Darmstadt)
- Tobias Stöckert (TU Darmstadt)
