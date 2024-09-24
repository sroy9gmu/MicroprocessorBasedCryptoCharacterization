# GnuPG setup steps

GitHub repos

    1. https://github.com/gpg/gnupg
    2. https://github.com/gpg/libgcrypt


Configuring hardware acceleration on target device

    Reference - https://www.gnupg.org/documentation/manuals/gcrypt/Hardware-features.html#Hardware-features
        1. sudo nano /etc/gcrypt/hwf.deny
        2. Add intel-aesni into the list


Installation

    1. Clone gnupg repo and change to its root directory
    2. Follow installation steps on its webpage
    3. Install missing packages as necessary
        sudo apt-get install graphicsmagick-imagemagick-compat fig2dev texinfo
    4. If facing automake errors, disable automake version check in autogen.sh and run below commands
        ./autogen.sh --force
        ./configure --sysconfdir=/etc --enable-maintainer-mode  && make
    5. On Raspbian, install missing packages as necessary
        apt-get install autotools-dev automake libfltk1.3-dev gettext
    6. If facing shared library errors, export LD_LIBRARY_PATH=/usr/local/lib

    7. Clone libgcrypt repo inside gnupg root directory
    8. cd libgcrypt-xxx/ && ./configure && make && sudo make install
    9. cd ../gnupg && ./configure && make && sudo make install
    10. If facing GPRT ACCESS error, update LD_LIBRARY_PATH and PATH environment variables

    11. If facing yacc command errors, run below commands
        sudo apt-get install bison -y
        sudo apt-get install byacc -y

    12. If facing font errors in gnupg:
        Makefile.am line 99
            else
            dirmngr =
            endif
            if BUILD_DOC
            #doc = doc
            else
            doc =
            endif
