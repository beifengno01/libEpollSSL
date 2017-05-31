//
// Created by root on 17-5-31.
//

#include "EpollSSL.hpp"

int cb(Reimu::EpollSSL::IOWrapper *io_ctx, void *userp) {

}

int main(){
	Reimu::EpollSSL::GlobalInit();

	sockaddr_in sss;

	sss.sin_family = AF_INET;
	sss.sin_addr.s_addr = INADDR_ANY;
	sss.sin_port = htons(1500);

	Reimu::EpollSSL es;

	es.Threads = 4;
	es.BindAddr = (sockaddr *)&sss;
	es.CertPath = "/etc/ssl/certs/ssl-cert-snakeoil.pem";
	es.PrivKeyPath = "/etc/ssl/private/ssl-cert-snakeoil.key";
	es.Callback = &cb;
	es.Server();


}