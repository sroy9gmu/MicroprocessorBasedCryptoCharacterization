# OpenSSL setup steps


Installation

    1. git clone https://github.com/openssl/openssl.git
    2. cd openssl
    3. ./Configure
    4. make
    5. make test (Optional)
    6. sudo make install


In case of shared library errors

    1. sudo cp *.so.3 /usr/local/lib
    2. sudo ldconfig