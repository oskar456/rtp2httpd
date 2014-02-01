/*
 *  RTP2HTTP Proxy - Multicast RTP stream to UNICAST HTTP translator
 *
 *  Copyright (C) 2008-2010 Ondrej Caletka <o.caletka@sh.cvut.cz>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rtp2httpd.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define BUFLEN 50
#define UDPBUFLEN 2000

static const char unimplemented[] =
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
"<html><head>\r\n"
"<title>501 Method Not Implemented</title>\r\n"
"</head><body>\r\n"
"<h1>501 Method Not Implemented</h1>\r\n"
"<p>Sorry, only GET is supported.</p>\r\n"
"<hr>\r\n"
"<address>Server " PACKAGE " version " VERSION "</address>\r\n"
"</body></html>\r\n";

static const char badrequest[] =
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
"<html><head>\r\n"
"<title>400 Bad Request</title>\r\n"
"</head><body>\r\n"
"<h1>400 Bad Request</h1>\r\n"
"<p>Your browser sent a request that this server could not understand.<br />\r\n"
"</p>\r\n"
"<hr>\r\n"
"<address>Server " PACKAGE " version " VERSION "</address>\r\n"
"</body></html>\r\n";

static const char serviceNotFound[] =
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
"<html><head>\r\n"
"<title>404 Service not found!</title>\r\n"
"</head><body>\r\n"
"<h1>404 Service not found!</h1>\r\n"
"<p>Sorry, this service was not configured.</p>\r\n"
"<hr>\r\n"
"<address>Server " PACKAGE " version " VERSION "</address>\r\n"
"</body></html>\r\n";

static const char serviceUnavailable[] =
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
"<html><head>\r\n"
"<title>503 Service Unavaliable</title>\r\n"
"</head><body>\r\n"
"<h1>503 Service Unavaliable</h1>\r\n"
"<p>Sorry, there are too many connections at this time.\r\n"
"Try again later.</p>\r\n"
"<hr>\r\n"
"<address>Server " PACKAGE " version " VERSION "</address>\r\n"
"</body></html>\r\n";

static const char *responseCodes[] = {
	"HTTP/1.1 200 OK\r\n",			/* 0 */
	"HTTP/1.1 404 Not Found\r\n",		/* 1 */
	"HTTP/1.1 400 Bad Request\r\n",		/* 2 */
	"HTTP/1.1 501 Not Implemented\r\n",	/* 3 */
	"HTTP/1.1 503 Service Unavailable\r\n",	/* 4 */
};

#define STATUS_200 0
#define STATUS_404 1
#define STATUS_400 2
#define STATUS_501 3
#define STATUS_503 4

static const char *contentTypes[] = {
	"Content-Type: application/octet-stream\r\n",	/* 0 */
	"Content-Type: text/html\r\n",		/* 1 */
	"Content-Type: text/html; charset=utf-8\r\n",	/* 2 */
	"Content-Type: video/mpeg\r\n",		/* 3 */
	"Content-Type: audio/mpeg\r\n",		/* 4 */
};

#define CONTENT_OSTREAM 0
#define CONTENT_HTML 1
#define CONTENT_HTMLUTF 2
#define CONTENT_MPEGV 3
#define CONTENT_MPEGA 4

static const char staticHeaders[] =
"Server: " PACKAGE "/" VERSION "\r\n"
"\r\n";

/*
 * Linked list of allowed services
 */

struct services_s *services = NULL;


/*
 * Ensures that all data are written to the socket
 */
inline void writeToClient(int s,const uint8_t *buf, const size_t buflen) {
	ssize_t actual;
	size_t written=0;
	while (written<buflen) {
		actual = write(s, buf+written, buflen-written);
		if (actual <= 0) {
			exit(RETVAL_WRITE_FAILED);
		}
		written += actual;
	}
}

/*
 * Send a HTTP/1.x response header
 * @params s socket
 * @params status index to responseCodes[] array
 * @params type index to contentTypes[] array
 */
inline void headers(int s, int status, int type) {
	writeToClient(s, (uint8_t*) responseCodes[status],
			strlen(responseCodes[status]));
	writeToClient(s, (uint8_t*) contentTypes[type],
			strlen(contentTypes[type]));
	writeToClient(s, (uint8_t*) staticHeaders,
			sizeof(staticHeaders)-1);
}


void sigpipe_handler(int signum) {
	exit(RETVAL_WRITE_FAILED);
}

/**
 * Parses URL in UDPxy format, i.e. /rtp/<maddr>:port
 * returns a pointer to statically alocated service struct if success,
 * NULL otherwise.
 */

static struct services_s* udpxy_parse(char* url) {
	static struct services_s serv;
	static struct addrinfo res_ai;
	static struct sockaddr_storage res_addr;

	char *addrstr, *portstr;
	int i, r;
	char c;
	struct addrinfo hints, *res;


	if (strncmp("/rtp/", url, 5) == 0)
		serv.service_type = SERVICE_MRTP;
	else if (strncmp("/udp/", url, 5) == 0)
		serv.service_type = SERVICE_MUDP;
	else
		return NULL;
	addrstr = rindex(url, '/');
	if (!addrstr)
		return NULL;
	/* Decode URL encoded strings */
	for (i=0; i<strlen(addrstr); i++) {
		if (addrstr[i] == '%' &&
		    sscanf(addrstr+i+1, "%2hhx", (unsigned char *) &c) >0 ) {
			addrstr[i] = c;
			memmove(addrstr+i+1, addrstr+i+3, 1+strlen(addrstr+i+3));
		}
	}
	logger(LOG_DEBUG, "decoded addr: %s\n", addrstr);
	if (addrstr[1] == '[') {
		portstr = index(addrstr, ']');
		addrstr += 2;
		if (portstr) {
			*portstr = '\0';
			portstr = rindex(++portstr, ':');
		}
	} else {
		portstr = rindex(addrstr++, ':');
	}
	if (portstr) {
		*portstr = '\0';
		portstr++;
	} else
		portstr = "1234";
	logger(LOG_DEBUG, "addrstr: %s portstr: %s\n", addrstr, portstr);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	r = getaddrinfo(addrstr, portstr, &hints, &res);
	if (r) {
		logger(LOG_ERROR, "Cannot resolve Multicast address. GAI: %s\n",
		       gai_strerror(r));
		return NULL;
	}
	if (res->ai_next != NULL) {
		logger(LOG_ERROR, "Warning: maddr is ambiguos.\n");
	}
	/* Copy result into statically allocated structs */
	memcpy(&res_addr, res->ai_addr, res->ai_addrlen);
	memcpy(&res_ai, res, sizeof(struct addrinfo));
	res_ai.ai_addr = (struct sockaddr*) &res_addr;
	res_ai.ai_canonname = NULL;
	res_ai.ai_next = NULL;
	serv.addr = &res_ai;

	return &serv;
}


static void startRTPstream(int client, struct services_s *service){
	int sock, level;
	int r;
	struct group_req gr;
	uint8_t buf[UDPBUFLEN];
	int actualr;
	uint16_t seqn, oldseqn, notfirst=0;
	int payloadstart, payloadlength;
	fd_set rfds;
	struct timeval timeout;
	int on = 1;

	sock = socket(service->addr->ai_family, service->addr->ai_socktype, 
			service->addr->ai_protocol);
        r = setsockopt(sock, SOL_SOCKET,
                        SO_REUSEADDR, &on, sizeof(on));
        if (r) {
                logger(LOG_ERROR, "SO_REUSEADDR "
                "failed: %s\n", strerror(errno));
        }
	r = bind(sock,(struct sockaddr *) service->addr->ai_addr, service->addr->ai_addrlen);
	if (r) {
		logger(LOG_ERROR, "Cannot bind: %s\n",
				strerror(errno));
		exit(RETVAL_RTP_FAILED);
	}
	memcpy(&(gr.gr_group), service->addr->ai_addr, service->addr->ai_addrlen);

	switch (service->addr->ai_family) {
		case AF_INET:
			level = SOL_IP;
			gr.gr_interface = 0;
			break;
			
		case AF_INET6:
			level = SOL_IPV6;
			gr.gr_interface = ((const struct sockaddr_in6 *)
				(service->addr->ai_addr))->sin6_scope_id;
			break;
		default:
			logger(LOG_ERROR, "Address family don't support mcast.\n");
			exit(RETVAL_SOCK_READ_FAILED);
	}			 

	r = setsockopt(sock, level,
		MCAST_JOIN_GROUP, &gr, sizeof(gr));
	if (r) {
		logger(LOG_ERROR, "Cannot join mcast group: %s\n",
				strerror(errno));
		exit(RETVAL_RTP_FAILED);
	}



	while(1) {
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		FD_SET(client, &rfds); /* Will be set if connection to client lost.*/
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		
		/* We use select to get rid of recv stuck if
		 * multicast group is unoperated.
		 */
		r=select(sock+1, &rfds, NULL, NULL, &timeout);
		if (r<0 && errno==EINTR)
			continue;
		if (r==0) { /* timeout reached */
			exit(RETVAL_SOCK_READ_FAILED);
		}
		if (FD_ISSET(client, &rfds)) { /* client written stg, or conn. lost	 */
			exit(RETVAL_WRITE_FAILED);
		}

		actualr = recv(sock, buf, sizeof(buf), 0);
		if (actualr < 0){
			exit(RETVAL_SOCK_READ_FAILED);
		}
		if (service->service_type == SERVICE_MUDP) {
			writeToClient(client, buf, sizeof(buf));
			continue;
		}
		
		if (actualr < 12 || (buf[0]&0xC0) != 0x80) { 
			/*malformed RTP/UDP/IP packet*/
			logger(LOG_DEBUG,"Malformed RTP packet received\n");
			continue;
		}

		payloadstart = 12; /* basic RTP header length */
		payloadstart += (buf[0]&0x0F) * 4; /*CRSC headers*/
		if (buf[0]&0x10) { /*Extension header*/
			payloadstart += 4 + 4*ntohs(*((uint16_t *)(buf+payloadstart+2)));
		}
		payloadlength = actualr - payloadstart;
		if (buf[0]&0x20) { /*Padding*/
			payloadlength -= buf[actualr]; 
			/*last octet indicate padding length*/
		}
		if(payloadlength<0) {
			logger(LOG_DEBUG,"Malformed RTP packet received\n");
			continue;
		}
		seqn = ntohs(*((uint16_t *)(buf+2)));
		if (notfirst && seqn==oldseqn) {
			logger(LOG_DEBUG,"Duplicated RTP packet "
				"received (seqn %d)\n", seqn);
			continue;
		}
		if (notfirst && (seqn != ((oldseqn+1)&0xFFFF))) {
			logger(LOG_DEBUG,"Congestion - expected %d, "
				"received %d\n", (oldseqn+1)&0xFFFF, seqn);
		}
		oldseqn=seqn;
		notfirst=1;

		writeToClient(client, buf+payloadstart, payloadlength);
	}

	/*SHOULD NEVER REACH THIS*/
	return;
}

/*
 * Service for connected client.
 * Run in forked thread.
 */
void clientService(int s) {
	char buf[BUFLEN];
	FILE *client;
	int numfields;
	char *method, *url, httpver;
	char *urlfrom;
	struct services_s *servi;

	signal(SIGPIPE, &sigpipe_handler);

	client = fdopen(s, "r"); 
	/*read only one line*/
	if (fgets(buf, sizeof(buf), client) == NULL) {
		exit(RETVAL_READ_FAILED);
	}
	numfields = sscanf(buf,"%as %as %c", &method, &url, &httpver);
	if(numfields<2) {
		logger(LOG_DEBUG, "Non-HTTP input.\n");
	}
	logger(LOG_DEBUG,"request: %s %s \n", method, url);

	if(numfields == 3) { /* Read and discard all headers before replying */
		while(fgets(buf, sizeof(buf), client) != NULL &&
			strcmp("\r\n", buf) != 0);
	}

	if (strcmp(method, "GET") != 0) {
		if (numfields == 3) 
			headers(s, STATUS_501, CONTENT_HTML);
		writeToClient(s, (uint8_t*) unimplemented, sizeof(unimplemented)-1);
		exit(RETVAL_UNKNOWN_METHOD);
	}
	free(method); method=NULL;

	urlfrom = rindex(url, '/');
	if (urlfrom == NULL) {
		if (numfields == 3) 
			headers(s, STATUS_400, CONTENT_HTML);
		writeToClient(s, (uint8_t*) badrequest, sizeof(badrequest)-1);
		exit(RETVAL_BAD_REQUEST);
	}

	for (servi = services; servi; servi=servi->next) {
		if (strcmp(urlfrom+1, servi->url) == 0)
			break;
	}

	if (servi == NULL && conf_udpxy)
		servi = udpxy_parse(url);

	free(url); url=NULL;

	if (servi == NULL) {
		if (numfields == 3) 
			headers(s, STATUS_404, CONTENT_HTML);
		writeToClient(s, (uint8_t*) serviceNotFound, sizeof(serviceNotFound)-1);
		exit(RETVAL_CLEAN);
	}

	if (clientcount > conf_maxclients) { /*Too much clients*/
		if (numfields == 3) 
			headers(s, STATUS_503, CONTENT_HTML);
		writeToClient(s, (uint8_t*) serviceUnavailable, sizeof(serviceUnavailable)-1);
		exit(RETVAL_CLEAN);
	}

	if (numfields == 3)
		headers(s, STATUS_200, CONTENT_OSTREAM);
	startRTPstream(s, servi);
	/* SHOULD NEVER REACH HERE */
	exit(RETVAL_CLEAN);
}
