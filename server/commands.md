/*Server command*/

openssl s_server -cert certs/test_cert.pem -key certs/test_key.pem -state -debug

//Client command
(echo "HI"; sleep 10) | openssl s_client -connect 128.105.14.108:4433 -debug -state

