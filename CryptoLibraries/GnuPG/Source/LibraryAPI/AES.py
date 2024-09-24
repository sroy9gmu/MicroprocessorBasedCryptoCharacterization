# https://tutonics.com/2012/11/gpg-encryption-guide-part-4-symmetric.html
# https://www.nas.nasa.gov/hecc/support/kb/using-gpg-to-encrypt-your-data_242.html
# https://security.stackexchange.com/questions/42459/gnupg-inner-workings-encryption-scheme-mode-of-operation-ciphers
import sys
import os
import subprocess
import shutil
import time
from statistics import geometric_mean

num_cmd_iter = 1#000
curr_dir = ""
results_dir = ""
file_to_encrypt = ""
password = ""
password_file = ""
algo_family = ""
cmd_crypto_lib = "cat {} | /usr/local/bin/gpg --yes --pinentry-mode loopback --passphrase-fd 0 -o "
cmd_parameters_enc = "{} --symmetric --cipher-algo {} {}"
cmd_parameters_dec = "{} -d {}"
cmd_file_to_encrypt = ""
cmd_redirect_op = " > "
tmp_files = []
algorithms = ["AES"]
ciphers_all = ["AES256"]

def main(): 
    global file_to_encrypt, password, algo_family, tmp_files, password_file
    ciphers = [] 
    
    if len(sys.argv) < 2:
        print("Incomplete command usage. Type \"python3 " + sys.argv[0] + " --help/-help/-h/--h\" for information.")
        sys.exit()      
    
    if sys.argv[1] in ["--help", "-help", "-h", "--h"]:
        show_help()
        sys.exit()

    file_to_encrypt = sys.argv[1]
    if not os.path.isfile(file_to_encrypt):
       print("File path {} does not exist. Exiting...".format(file_to_encrypt))
       sys.exit()   
       
    out_foldername = sys.argv[2]
    if len(sys.argv) == 5:
        algo_family = sys.argv[3]
        for cipher in ciphers_all:
            if algo_family in cipher:
                ciphers.append(cipher)
        password_file = sys.argv[4]
        get_passwd(sys.argv[4])        
    else:
        password_file = sys.argv[3]
        get_passwd(sys.argv[3])        
        ciphers = ciphers_all
    create_result_dir(out_foldername)
    
    ciphers.sort()     

    get_exec_times(ciphers)    

# @profile
def mem_enc(cmd):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# @profile
def mem_dec(cmd):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
     
def get_passwd(filename):
    global password
    
    if not os.path.exists(filename):
        print("Password file does not exist!")
        exit()
    else:    
        fp = open(filename, 'r')
        password = fp.read()
        fp.close()    
    
def create_result_dir(foldername):
    global curr_dir, results_dir
    is_rerun = False
    
    curr_dir = os.getcwd()    
    results_dir = os.path.join(curr_dir, foldername)
    if os.path.exists(results_dir):
        is_rerun = True
        shutil.rmtree(results_dir)
    access_rights = 0o755
    try:
        os.mkdir(results_dir, access_rights)
    except OSError:
        print ("Creation of the directory {} failed".format(results_dir))
    else:
        if is_rerun == False:
            print ("Successfully created the directory {}".format(results_dir))
        else:
            print ("Successfully re-created the directory {}".format(results_dir))
                 
def get_exec_times(ciphers):
    global file_to_encrypt, output_file, tmp_files, password, password_file
    
    fp_pt = open(file_to_encrypt)
    msg = fp_pt.read()
    fp_pt.close()
    
    fp_time = open(os.path.join(results_dir, "ProfilingTimes"), 'a')
       
    for algo in ciphers:  
       	fp_time.write("{}\n".format(algo))

        # Perform encryption for required number of times  
        enc_all_dur = []
        enc_all_ops = []
        enc_all_lens = []
        fp_time.write("Encryption start time = {}.\n".format(time.asctime()))
        for it in range(num_cmd_iter):
            enc_all_ops.append(file_to_encrypt + ".enc." + str(it))
            tmp_files.append(enc_all_ops[it])
            enc_cmd = cmd_crypto_lib.format(password_file) + cmd_parameters_enc.format(enc_all_ops[it], algo, file_to_encrypt)
            enc_it_start = time.time()
            # Enable for memory usage only
            # mem_enc(enc_cmd)
            #subprocess.run(enc_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(enc_cmd, shell=True)
            enc_it_end = time.time()
            enc_all_dur.append(enc_it_end - enc_it_start)
            # Enable lines 129 till 131 for ciphertext length profiling
            # with open(enc_all_ops[it], 'rb') as fp:
            #     ct = fp.read()
            # enc_all_lens.append(len(ct))
        fp_time.write("Encryption end time = {}.\n".format(time.asctime()))
        enc_mean_dur = geometric_mean(enc_all_dur)
        fp_time.write("Encryption mean duration for {} iterations = {} seconds.\n".format(num_cmd_iter, enc_mean_dur))
        # Enable lines 135 till 140 for ciphertext length profiling
        # if enc_all_lens.count(enc_all_lens[0]) != len(enc_all_lens):
        #     fp_time.write("Ciphertext length varies across iterations.\n")
        #     fp_time.write("Maximum ciphertext length (bytes) = {}.\n".format(max(enc_all_lens)))
        # else:
        #     fp_time.write("Ciphertext length (bytes) = {}.\n".format(enc_all_lens[0]))

        # Perform decryption for required number of times
        dec_all_dur = []
        dec_all_ops = []
        fp_time.write("Decryption start time = {}.\n".format(time.asctime()))
        for it in range(num_cmd_iter):
            dec_all_ops.append(file_to_encrypt + ".dec." + str(it))
            tmp_files.append(dec_all_ops[it])
            dec_cmd = cmd_crypto_lib.format(password_file) + cmd_parameters_dec.format(dec_all_ops[it], \
                file_to_encrypt + ".enc." + str(it))
            dec_it_start = time.time()
            # Enable for memory usage only
            # mem_dec(dec_cmd)
            #subprocess.run(dec_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(dec_cmd, shell=True)
            dec_it_end = time.time()
            dec_all_dur.append(dec_it_end - dec_it_start)
        fp_time.write("Decryption end time = {}.\n".format(time.asctime()))
        dec_mean_dur = geometric_mean(dec_all_dur)
        fp_time.write("Decryption mean duration for {} iterations = {} seconds.\n".format(num_cmd_iter, dec_mean_dur))
            
        # Check for correctness of decrypted outputs       
        err_found = False
        for it in range(num_cmd_iter):
            if os.path.exists(dec_all_ops[it]) == False:
                print("Decrypted file {} does not exist!".format(dec_all_ops[it]))
            else:
                fp_dt = open(dec_all_ops[it])
                dt = fp_dt.read()
                fp_dt.close()
                if dt != msg:
                    fp_time.write("Decryption error occured in {} iteration.".format(it))
                    fp_time.write("Actual text: {}".format(dt))
                    fp_time.write("Original text: {}".format(msg))
                    if err_found == False:
                        err_found = True
        if err_found == False:
            fp_time.write("No decryption error occured.")

        clean_folder()
    
    fp_time.close()
           
def show_help():
    print("Usage: python3 " + sys.argv[0] +\
        " [file to be encrypted/decrypted] [results foldername] [algorithm] [password file]")
    print("Values for \'algorithm\': (executes all if not specified)")
    print(', '.join(map(str, algorithms))) 
        
def clean_folder():
    for file in tmp_files:
        if os.path.exists(file):
            os.remove(file)
        
if __name__ == '__main__':
    main()
