#!/bin/bash

clean() {
	rm ca -r
	rm server -r
	mkdir ca
	mkdir server
}

genrsakey() {
	#https://my.oschina.net/itblog/blog/651434
	#root 端
	#ca 端
	#生成密钥 aes256 加密
	openssl genrsa -aes256 -passout pass:$2 -out $1/pri_key.pem 2048
}

genecckey() {
	#https://my.oschina.net/itblog/blog/651434
	openssl ecparam -genkey -name secp256k1 | openssl ec -aes256 -out $1/pri_key.pem -passout pass:$2
}

getnrootca() {
	# 不用请求文件 直接生成证书
	openssl req -new -x509 -days 36500 -sha256 -extensions v3_ca -key $1/pri_key.pem \
		-out ca/ca.cer -subj "/C=CN/ST=myprovince/L=mycity/O=myorganization/OU=mygroup/CN=*.kvm" -passin pass:$2
}

getcaReq() {
	# 使用服务端密钥 生成证书申请文件
	# CN common name一定要与根证书CN不一样
	openssl req -new -key $1/pri_key.pem -out $1/pri.csr -subj \
		"/C=CN/ST=myprovince/L=mycity/O=myorganization/OU=mygroup/CN=server.kvm" -passin pass:$2
	# 使用申请文件 root 私钥  root证书 签发 server.ca
	openssl x509 -req -days 20 -sha256 -extensions v3_req -CA $3/ca.cer -CAkey $3/pri_key.pem \
		-in $1/pri.csr -out $1/pri.ca -CAcreateserial -passin pass:$4
}

genpfx() {
	#产生pfx 私钥-证书文件用于 win server
	openssl pkcs12 -export -out $1/server.pfx -inkey $1/pri_key.pem -passin pass:$2 -in $1/pri.ca -passout pass:
}
pri_path=ca
pri_pass=12138
root_path=ca
root_pass=12138

ca_path=ca
ca_pass=12138

server_path=server
server_pass=12139

client_path=client
client_pass=12140

mkdir -p ca
mkdir -p server

[ -f $root_path/ca.cer -a -f $root_path/pri_key.pem ] || {
	echo "gen root key ca"
	genrsakey $ca_path $ca_pass
	getnrootca $ca_path $ca_pass
}

echo "gen server key"
genrsakey $server_path $server_pass
echo "gen server cert"
getcaReq $server_path $server_pass $ca_path $ca_pass
genpfx $server_path $server_pass

echo "gen client key"
genrsakey $client_path $client_pass
echo "gen client cert"
getcaReq $client_path $client_pass $ca_path $ca_pass
