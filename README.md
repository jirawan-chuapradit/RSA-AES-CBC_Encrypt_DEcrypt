# RSA-AES-CBC_Encrypt_Decrypt

> Using RSA to Encrypt Front-end Public Key and Decrypt Back-end Private Key

 
 **Require** <br>
 - OpenSSL <br>
 - Go <br>
 <hr>
 
 Step 1: Install OpenSSL <br>
 Step 2: Generating keys using OpenSSL <br>
 
  > #### Generating keys using OpenSS <br>
  > **Generating a private RSA key** <br>
  > - Generate an RSA private key, of size 2048, and output it to a file named key.pem:
  > 
  >       $ openssl genpkey -aes-256-cbc -algorithm RSA -out key2.pem -pkeyopt rsa_keygen_bits:2048
  > - Extract the public key from the key pair, which can be used in a certificate: <br>
  > 
  >       $ openssl rsa -in key2.pem -outform PEM -pubout -out public2.pem
  >  see more: [Generating_keys_using_OpenSSL](https://developers.yubico.com/PIV/Guides/Generating_keys_using_OpenSSL.html).

 Step 3: Run <br>
 
        $ go run .
