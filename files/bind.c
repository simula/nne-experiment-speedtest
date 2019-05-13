// =================================================================
//          #     #                 #     #
//          ##    #   ####   #####  ##    #  ######   #####
//          # #   #  #    #  #    # # #   #  #          #
//          #  #  #  #    #  #    # #  #  #  #####      #
//          #   # #  #    #  #####  #   # #  #          #
//          #    ##  #    #  #   #  #    ##  #          #
//          #     #   ####   #    # #     #  ######     #
//
//       ---   The NorNet Testbed for Multi-Homed Systems  ---
//                       https://www.nntb.no
// =================================================================
//
// bind() wrapper
//
// Copyright (C) 2018-2019 by Thomas Dreibholz
// Copyright (C) 2000 by Daniel Ryde
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Contact: dreibh@simula.no

/*
   LD_PRELOAD library to make bind and connect to use a virtual
   IP address as localaddress. Specified via the enviroment
   variable BIND_ADDR.

   Compile on Linux with:
   gcc -nostartfiles -fpic -shared bind.c -o bind.so -ldl -D_GNU_SOURCE


   Example in bash to make inetd only listen to the localhost
   lo interface, thus disabling remote connections and only
   enable to/from localhost:

   BIND_ADDR="127.0.0.1" LD_PRELOAD=./bind.so /sbin/inetd


   Example in bash to use your virtual IP as your outgoing
   sourceaddress for ircII:

   BIND_ADDR="your-virt-ip" LD_PRELOAD=./bind.so ircII

   Note that you have to set up your servers virtual IP first.


   This program was made by Daniel Ryde
   email: daniel@ryde.net
   web:   http://www.ryde.net/

   TODO: I would like to extend it to the accept calls too, like a
   general tcp-wrapper. Also like an junkbuster for web-banners.
   For libc5 you need to replace socklen_t with int.
*/


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <errno.h>
#include <error.h>
#include <netdb.h>

#include <dlfcn.h>

#include <resolv.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>

static int (*real_bind)(int, const struct sockaddr*, socklen_t);
static int (*real_connect)(int, const struct sockaddr*, socklen_t);

static char*              bind_addr_env;
static unsigned long int  bind_addr_saddr;
static unsigned long int  inaddr_any_saddr;
static struct sockaddr_in local_sockaddr_in[] = { 0 };


// ###### Print debug information ############################################
static void debug(const char* info, const struct sockaddr* sa)
{
   if( (sa->sa_family == AF_INET) || (sa->sa_family == AF_INET6) ) {
      char addressString[NI_MAXHOST];
      char portString[NI_MAXSERV];
      int  result = getnameinfo(sa, sizeof(struct sockaddr_storage),
                                (char*)&addressString, sizeof(addressString),
                                (char*)&portString, sizeof(portString),
                                NI_NUMERICHOST|NI_NUMERICSERV);
      if(result != 0) {
         strcpy((char*)&addressString, "???");
         strcpy((char*)&portString, "?");
      }
      fprintf(stderr, "%s: %s:%s\n", info, addressString, portString);
   }
}


// ###### Initialize ########################################################
void _init (void)
{
   const char* err;

   // ====== Store pointers to actual bind() and connect() functions ========
   real_bind = dlsym(RTLD_NEXT, "bind");
   if((err = dlerror()) != NULL) {
      fprintf(stderr, "dlsym (bind): %s\n", err);
   }
   real_connect = dlsym(RTLD_NEXT, "connect");
   if((err = dlerror()) != NULL) {
      fprintf(stderr, "dlsym (connect): %s\n", err);
   }

   // ====== Initialise local IPv4 address ==================================
   inaddr_any_saddr = htonl(INADDR_ANY);
   if((bind_addr_env = getenv("BIND_ADDR")) != NULL) {
      bind_addr_saddr = inet_addr (bind_addr_env);
      local_sockaddr_in->sin_family      = AF_INET;
      local_sockaddr_in->sin_addr.s_addr = bind_addr_saddr;
      local_sockaddr_in->sin_port        = htons(0);
   }
}


// ###### bind() wrapper ####################################################
int bind (int fd, const struct sockaddr* sk, socklen_t sl)
{
   struct sockaddr_in* lsk_in = (struct sockaddr_in*)sk;

   // ====== Bind IPv4 socket to BIND_ADDR ==================================
   // debug("bind", sk);
   if((lsk_in->sin_family == AF_INET) &&
      (lsk_in->sin_addr.s_addr == inaddr_any_saddr) &&
      (bind_addr_env)) {
      lsk_in->sin_addr.s_addr = bind_addr_saddr;
   }

   return real_bind(fd, sk, sl);
}


// ###### connect() wrapper #################################################
int connect (int fd, const struct sockaddr* sk, socklen_t sl)
{
   struct sockaddr_in* rsk_in = (struct sockaddr_in*)sk;

   // ====== Bind IPv4 socket to BIND_ADDR ==================================
   if((rsk_in->sin_family == AF_INET) && (bind_addr_env)) {   // Only for IPv4!
      // debug("bind", (struct sockaddr*)local_sockaddr_in);
      if((ntohl(rsk_in->sin_addr.s_addr) & 0x7f000000) != 0x7f000000) {   // Only for non-loopback remote addresses!
         // Newer Ubuntu systems use 127.0.0.53 as DNS resolver. This does not
         // work when the socket is bound to a certain NIC's address!
         real_bind(fd, (struct sockaddr*)local_sockaddr_in, sizeof(struct sockaddr));
      }
   }

   // debug("connect", sk);
   return real_connect(fd, sk, sl);
}


#define super() dlsym(RTLD_NEXT, __func__)

#ifdef DEBUG
static void
_print_ns(res_state res)
{
   FILE*        log;
   char         buf[16];
   const char*  logfile;
   unsigned int i;
   time_t       now = time(NULL);

   if( NULL == ( logfile = getenv("RESOLV_NS_OVERRIDE_LOG") ))
      return;

   if(strcmp("-", logfile) == 0) {
      log = stderr;
   } else if( NULL == (log = fopen(logfile, "a") )) {
      error(0, errno, "could not open resolv-ns-override log file %s",
            logfile);
      return;
   }

   if( log == stderr )
      fprintf(log, "\n");
   else
      fprintf(log, "%s", ctime(&now));

   for(i = 0; i < res->nscount; i++) {
      inet_ntop(AF_INET, &res->nsaddr_list[i].sin_addr, buf, sizeof(buf));
      fprintf(log, "  configured nameserver %u: %s:%u\n",
              i + 1, buf, ntohs(res->nsaddr_list[i].sin_port));
   }
   fprintf(log, "\n");

   if( log != stderr )
      fclose(log);
}
#else
#define _print_ns(X)
#endif

int
__res_maybe_init(res_state res, int preinit)
{
   const char*         nameserver;
   struct sockaddr_in* addr;
   char                envvar[] = "NAMESERVER0";
   int                 ret, count, i;

   int (*f)(res_state, int) = super();
   assert(f);
   ret = f(res, preinit);

   count = res->nscount;
   res->nscount = 0;
   for(i = 0; (res->nscount < MAXNS) && (i < 10); i++) {
      envvar[10]++;
      if( (nameserver = getenv(envvar)) == NULL )
         continue;
      addr = &res->nsaddr_list[i];
      if( inet_pton(AF_INET, nameserver, &addr->sin_addr) < 1 ) {
         error(0, errno, "failed to set name server address");
         continue;
      }
      addr->sin_family = AF_INET;
      addr->sin_port   = htons(NAMESERVER_PORT);
      res->nscount++;
   }

   if(!res->nscount)
      res->nscount = count;

   _print_ns(res);

   return ret;
}
