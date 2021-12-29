#!/bin/bash

pri_path=
pri_pass=12138

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
	openssl genrsa -aes256 -passout pass:$pri_pass -out $pri_path/pri_key.pem 2048
}

genecckey() {
	#https://my.oschina.net/itblog/blog/651434
	openssl ecparam -genkey -name secp256k1 | openssl ec -aes256 -out $pri_path/pri_key.pem -passout pass:$pri_pass
}

getnrootca() {
	# 不用请求文件 直接生成证书
	openssl req -new -x509 -days 36500 -sha256 -extensions v3_ca -key $pri_path/pri_key.pem \
		-out ca/ca.cer -subj "/C=CN/ST=myprovince/L=mycity/O=myorganization/OU=mygroup/CN=*.kvm" -passin pass:$pri_pass
}

getcaReq() {
	# 使用服务端密钥 生成证书申请文件
	# CN common name一定要与根证书CN不一样
	openssl req -new -key $pri_path/pri_key.pem -out $pri_path/pri.csr -subj \
		"/C=CN/ST=myprovince/L=mycity/O=myorganization/OU=mygroup/CN=server.kvm" -passin pass:$pri_pass
	# 使用申请文件 root 私钥  root证书 签发 server.ca
	openssl x509 -req -days 20 -sha256 -extensions v3_req -CA $root_path/ca.cer -CAkey $root_path/pri_key.pem \
		-in $pri_path/pri.csr -out $pri_path/pri.ca -CAcreateserial -passin pass:$root_pass
}

genpfx() {
	#产生pfx 私钥-证书文件用于 win server
	openssl pkcs12 -export -out $pri_path/server.pfx -inkey $pri_path/pri_key.pem -passin pass:$pri_pass -in $pri_path/pri.ca -passout pass:
}
pri_path=ca
pri_pass=12138
root_path=ca
root_pass=12138

mkdir -p ca
mkdir -p server

[ -f $root_path/ca.cer -a -f $root_path/pri_key.pem ] || {
	echo "gen root key ca"
	genrsakey
	getnrootca
}

pri_path=server
pri_pass=12138
echo "gen pri key"
genrsakey
echo "gen pri ca"
getcaReq
genpfx