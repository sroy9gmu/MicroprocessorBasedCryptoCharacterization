# wolfSSL setup steps

GitHub repos

    1. wolfSSL (Parent) - https://github.com/wolfSSL/wolfssl
    2. wolfCLU (Child) - https://github.com/wolfSSL/wolfCLU


Installation of wolfSSL

    1. git clone https://github.com/wolfSSL/wolfssl.git
    2. ./autogen.sh (for raspbian, sudo apt-get install autoconf libtool)
    3. ./configure --enable-wolfclu --enable-aescfb --enable-aesctr --enable-sha224 --enable-pwdbased   
    4. make
    5. make check (Optional)
    6. sudo make install


Installation of wolfCLU

    1. git clone https://github.com/wolfSSL/wolfCLU.git
    2. ./autogen.sh 
    3. ./configure
    4. make
    5. make check (Optional)
    6. sudo make install
    7. sudo ldconfig


In case of shared library errors

    1. gedit ~/.bashrc -> export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    2. source ~/.bashrc 
    3. sudo ldconfig









