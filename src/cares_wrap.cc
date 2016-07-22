/*
The follwoing code adapted from node's dns module and license is as follows
*/

// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#define CARES_STATICLIB
#include "../deps/cares/include/ares.h"
#include "../deps/cares/src/ares_dns.h"
#include "nan.h"
#include "tree.h"
#include "uv.h"

#if defined(__ANDROID__) || \
    defined(__OpenBSD__) || \
    defined(__MINGW32__) || \
    defined(_MSC_VER)

# include <nameser.h>
#else
# include <arpa/nameser.h>
#endif


#ifndef offset_of
// g++ in strict mode complains loudly about the system offsetof() macro
// because it uses NULL as the base address.
# define offset_of(type, member) \
((intptr_t) ((char *) &(((type *) 8)->member) - 8))
#endif

#ifndef container_of
# define container_of(ptr, type, member) \
((type *) ((char *) (ptr) - offset_of(type, member)))
#endif

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif


// since uv_inet_pton and uv_inet_ntop signature varies from
// one version to another version of node, defining a warp function
// which takes care of version specfic implementation.
int wrap_uv_inet_pton(int af, const char* src, void* dst)
{
#if (NODE_MODULE_VERSION < NODE_0_12_MODULE_VERSION)
  return uv_inet_pton(af, src, dst).code;
#else
  return uv_inet_pton(af, src, dst);
#endif
}

int wrap_uv_inet_ntop(int af, const void* src, char* dst, size_t size)
{
#if (NODE_MODULE_VERSION < NODE_0_12_MODULE_VERSION)
  return uv_inet_ntop(af, src, dst, size).code;
#else
  return uv_inet_ntop(af, src, dst, size);
#endif
}


namespace Nan {

  namespace cares_wrap {

    using v8::Array;
    using v8::FunctionTemplate;
    using v8::Handle;
    using v8::HandleScope;
    using v8::Integer;
    using v8::Local;
    using v8::Object;
    using v8::Persistent;
    using v8::String;
    using v8::Value;

    static Nan::Persistent<String> oncomplete_sym;

    class Resolver;

    static void Callback(void *arg, int status, int timeouts,
                         unsigned char* answer_buf, int answer_len);

    static void GenericQueryCallback(void *arg, int status, int timeouts,
                                     unsigned char* answer_buf, int answer_len);

    static void Callback(void *arg, int status, int timeouts,
                         struct hostent* host);

    struct ares_task_t {
      UV_HANDLE_FIELDS
      Resolver* resolver;
      ares_socket_t sock;
      uv_poll_t poll_watcher;
      RB_ENTRY(ares_task_t) node;
    };



    static int cmp_ares_tasks(const ares_task_t* a, const ares_task_t* b) {
      if (a->sock < b->sock) return -1;
      if (a->sock > b->sock) return 1;
      return 0;
    }



    static void ares_sockstate_cb(void* data, ares_socket_t sock, int read, int write);

    class Resolver: public ObjectWrap {
    public:
      static void Initialize(Handle<Object> target);

      RB_HEAD(ares_task_list, ares_task_t) ares_tasks;
      RB_GENERATE(ares_task_list, ares_task_t, node, cmp_ares_tasks)

      inline ares_task_list* cares_task_list() {
        return &_ares_task_list;
      }

      inline uv_timer_t* cares_timer_handle() {
        return &ares_timer;
      }

      ares_channel _ares_channel;

    private:
      static NAN_METHOD(New);

      Resolver(Local<Object> options_obj)
      : ObjectWrap() {
        int r;
        int optmask = ARES_OPT_FLAGS | ARES_OPT_SOCK_STATE_CB;
        int flags = ARES_FLAG_NOCHECKRESP;

        RB_INIT(&_ares_task_list);

        struct ares_options options;
        memset(&options, 0, sizeof(options));
        options.sock_state_cb = ares_sockstate_cb;
        options.sock_state_cb_data = this;

        Local<Value> timeout_obj = options_obj->Get(Nan::New("timeout").ToLocalChecked());
        if (timeout_obj->IsNumber()) {
          options.timeout = (int)timeout_obj->Int32Value();
          optmask |= ARES_OPT_TIMEOUTMS;
        }

        Local<Value> tries_obj = options_obj->Get(Nan::New("tries").ToLocalChecked());
        if (tries_obj->IsNumber()) {
          options.tries = (int)tries_obj->Int32Value();
          optmask |= ARES_OPT_TRIES;
        }

        Local<Value> ndots_obj = options_obj->Get(Nan::New("ndots").ToLocalChecked());
        if (ndots_obj->IsNumber()) {
          options.ndots = (int)ndots_obj->Int32Value();
          optmask |= ARES_OPT_NDOTS;
        }

        Local<Value> tcp_port_obj = options_obj->Get(Nan::New("tcp_port").ToLocalChecked());
        if (tcp_port_obj->IsNumber()) {
          options.tcp_port = (int)tcp_port_obj->Uint32Value();
          optmask |=  ARES_OPT_TCP_PORT;
        }

        Local<Value> udp_port_obj = options_obj->Get(Nan::New("udp_port").ToLocalChecked());
        if (udp_port_obj->IsNumber()) {
          options.udp_port = (int)udp_port_obj->Uint32Value();
          optmask |=  ARES_OPT_UDP_PORT;
        }

        Local<Value> flags_obj = options_obj->Get(Nan::New("flags").ToLocalChecked());
        if (flags_obj->IsNumber()) {
          flags = flags | (int)flags_obj->Int32Value();
        }

        options.flags = flags;

        /* We do the call to ares_init_option for caller. */
        r = ares_init_options(&_ares_channel,
                              &options,
                              optmask);
        assert(r == ARES_SUCCESS);

        /* Initialize the timeout timer. The timer won't be started until the */
        /* first socket is opened. */

        ares_timer.data = this;
        uv_timer_init(uv_default_loop(), &ares_timer);
      }

      ~Resolver() {
        ares_destroy(this->_ares_channel);
      }

      ares_task_list _ares_task_list;
      uv_timer_t ares_timer;
    };


    /* This is called once per second by loop->timer. It is used to constantly */
    /* call back into c-ares for possibly processing timeouts. */
#if NODE_MODULE_VERSION < NODE_0_12_MODULE_VERSION
    static void ares_timeout(uv_timer_t* handle, int status) {
#else
    static void ares_timeout(uv_timer_t* handle) {
#endif
      Resolver *resolver = (Resolver*)handle->data;
      assert(!RB_EMPTY(resolver->cares_task_list()));
      ares_process_fd(resolver->_ares_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }

    static void ares_poll_cb(uv_poll_t* watcher, int status, int events) {
      ares_task_t* task = container_of(watcher, ares_task_t, poll_watcher);
      /* Reset the idle timer */
      uv_timer_again(task->resolver->cares_timer_handle());

      if (status < 0) {
        /* An error happened. Just pretend that the socket is both readable and */
        /* writable. */
        ares_process_fd(task->resolver->_ares_channel, task->sock, task->sock);
        return;
      }

      /* Process DNS responses */
      ares_process_fd(task->resolver->_ares_channel,
                      events & UV_READABLE ? task->sock : ARES_SOCKET_BAD,
                      events & UV_WRITABLE ? task->sock : ARES_SOCKET_BAD);
    }

    static void ares_poll_close_cb(uv_handle_t* watcher) {
      ares_task_t* task = container_of(watcher, ares_task_t, poll_watcher);
      free(task);
    }

    /* Allocates and returns a new ares_task_t */
    static ares_task_t* ares_task_create(Resolver* resolver, ares_socket_t sock) {
      ares_task_t* task = (ares_task_t*) malloc(sizeof *task);

      if (task == NULL) {
        /* Out of memory. */
        return NULL;
      }

      task->resolver = resolver;
      task->sock = sock;

      if (uv_poll_init_socket(uv_default_loop(), &task->poll_watcher, sock) < 0) {
        /* This should never happen. */
        free(task);
        return NULL;
      }

      return task;
    }

    /* Callback from ares when socket operation is started */
    static void ares_sockstate_cb(void* data, ares_socket_t sock, int read, int write) {

      Resolver *resolver = (Resolver*)data;
      ares_task_t* task;

      ares_task_t lookup_task;
      lookup_task.sock = sock;
      task = RB_FIND(resolver->ares_task_list, resolver->cares_task_list(), &lookup_task);

      if (read || write) {
        if (!task) {
          /* New socket */

          /* If this is the first socket then start the timer. */
          uv_timer_t* timer_handle = resolver->cares_timer_handle();
          if (!uv_is_active((uv_handle_t*) &timer_handle)) {
            assert(RB_EMPTY(resolver->cares_task_list()));
            uv_timer_start(timer_handle, ares_timeout, 100, 100);
          } else {
            //For some reason, sometimes execution comes to this block and gets hung.
            //TODO: Remove this dirty fix of calling uv_timer_start to handle this scenario.
            assert(RB_EMPTY(resolver->cares_task_list()));
            uv_timer_start(timer_handle, ares_timeout, 100, 100);
          }

          task = ares_task_create(resolver, sock);
          if (task == NULL) {
            /* This should never happen unless we're out of memory or something */
            /* is seriously wrong. The socket won't be polled, but the the query */
            /* will eventually time out. */
            return;
          }

          RB_INSERT(resolver->ares_task_list, resolver->cares_task_list(), task);
        }

        /* This should never fail. If it fails anyway, the query will eventually */
        /* time out. */
        uv_poll_start(&task->poll_watcher,
                      (read ? UV_READABLE : 0) | (write ? UV_WRITABLE : 0),
                      ares_poll_cb);

      } else {
        /* read == 0 and write == 0 this is c-ares's way of notifying us that */
        /* the socket is now closed. We must free the data associated with */
        /* socket. */
        assert(task &&
               "When an ares socket is closed we should have a handle for it");

        RB_REMOVE(resolver->ares_task_list, resolver->cares_task_list(), task);
        uv_close((uv_handle_t*) &task->poll_watcher, ares_poll_close_cb);

        if (RB_EMPTY(resolver->cares_task_list())) {
          uv_timer_stop(resolver->cares_timer_handle());
        }
      }
    }


    static const char* AresErrnoString(int errorno) {
      switch (errorno) {
#define ERRNO_CASE(e) case ARES_##e: return #e;
          ERRNO_CASE(SUCCESS)
          ERRNO_CASE(ENODATA)
          ERRNO_CASE(EFORMERR)
          ERRNO_CASE(ESERVFAIL)
          ERRNO_CASE(ENOTFOUND)
          ERRNO_CASE(ENOTIMP)
          ERRNO_CASE(EREFUSED)
          ERRNO_CASE(EBADQUERY)
          ERRNO_CASE(EBADNAME)
          ERRNO_CASE(EBADFAMILY)
          ERRNO_CASE(EBADRESP)
          ERRNO_CASE(ECONNREFUSED)
          ERRNO_CASE(ETIMEOUT)
          ERRNO_CASE(EOF)
          ERRNO_CASE(EFILE)
          ERRNO_CASE(ENOMEM)
          ERRNO_CASE(EDESTRUCTION)
          ERRNO_CASE(EBADSTR)
          ERRNO_CASE(EBADFLAGS)
          ERRNO_CASE(ENONAME)
          ERRNO_CASE(EBADHINTS)
          ERRNO_CASE(ENOTINITIALIZED)
          ERRNO_CASE(ELOADIPHLPAPI)
          ERRNO_CASE(EADDRGETNETWORKPARAMS)
          ERRNO_CASE(ECANCELLED)
#undef ERRNO_CASE
        default:
          assert(0 && "Unhandled c-ares error");
          return "(UNKNOWN)";
      }
    }


    static const unsigned char *fill_question(const unsigned char *aptr,
                                              const unsigned char *abuf,
                                              int alen,
                                              Local<Array> questions) {
      Local<Object> question = Nan::New<Object>();
      char *name;
      int type, dnsclass, status;
      long len;

      /* Parse the question name. */
      status = ares_expand_name(aptr, abuf, alen, &name, &len);
      if (status != ARES_SUCCESS)
        return NULL;
      aptr += len;

      /* Make sure there's enough data after the name for the fixed part
       * of the question.
       */
      if (aptr + NS_QFIXEDSZ > abuf + alen)
      {
        ares_free_string(name);
        return NULL;
      }

      /* Parse the question type and class. */
      type = DNS_QUESTION_TYPE(aptr);
      dnsclass = DNS_QUESTION_CLASS(aptr);
      aptr += NS_QFIXEDSZ;

      /* Display the question, in a format sort of similar to how we will
       * display RRs.
       */

      question->Set(Nan::New("name").ToLocalChecked(), Nan::New(name).ToLocalChecked());
      question->Set(Nan::New("type").ToLocalChecked(), Nan::New<Integer>(type));
      question->Set(Nan::New("class").ToLocalChecked(), Nan::New<Integer>(dnsclass));

      questions->Set(questions->Length(), question);

      ares_free_string(name);
      return aptr;
    }



    static const unsigned char *fill_rr(const unsigned char *aptr,
                                        const unsigned char *abuf,
                                        int alen,
                                        Local<Array> records) {
      Local<Object> record = Nan::New<Object>();
      const unsigned char *p;
      int type, dnsclass, ttl, dlen, status;
      long len;
      char addr[46];
      union {
        unsigned char * as_uchar;
        char * as_char;
      } name;

      /* Parse the RR name. */
      status = ares_expand_name(aptr, abuf, alen, &name.as_char, &len);
      if (status != ARES_SUCCESS)
        return NULL;
      aptr += len;

      /* Make sure there is enough data after the RR name for the fixed
       * part of the RR.
       */
      if (aptr + NS_RRFIXEDSZ > abuf + alen)
      {
        ares_free_string(name.as_char);
        return NULL;
      }

      /* Parse the fixed part of the RR, and advance to the RR data
       * field. */
      type = DNS_RR_TYPE(aptr);
      dnsclass = DNS_RR_CLASS(aptr);
      ttl = DNS_RR_TTL(aptr);
      dlen = DNS_RR_LEN(aptr);
      aptr += NS_RRFIXEDSZ;
      if (aptr + dlen > abuf + alen)
      {
        ares_free_string(name.as_char);
        return NULL;
      }

      /* Fill the RR name, class, and type. */
      record->Set(Nan::New("name").ToLocalChecked(), Nan::New(name.as_char).ToLocalChecked());
      record->Set(Nan::New("class").ToLocalChecked(), Nan::New<Integer>(dnsclass));
      record->Set(Nan::New("type").ToLocalChecked(), Nan::New<Integer>(type));
      record->Set(Nan::New("ttl").ToLocalChecked(), Nan::New<Integer>(ttl));
      ares_free_string(name.as_char);

      /* Display the RR data.  Don't touch aptr. */
      switch (type)
      {
        case ns_t_cname: //T_CNAME:
        case ns_t_mb: //T_MB:
        case ns_t_md: //T_MD:
        case ns_t_mf: //T_MF:
        case ns_t_mg: //T_MG:
        case ns_t_mr: //T_MR:
        case ns_t_ns: //T_NS:
        case ns_t_ptr: //T_PTR:
          /* For these types, the RR data is just a domain name. */
          status = ares_expand_name(aptr, abuf, alen, &name.as_char, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          record->Set(Nan::New("data").ToLocalChecked(), Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          break;

        case ns_t_hinfo: //T_HINFO:
        {
          /* The RR data is two length-counted character strings. */
          Local<Array> strings = Nan::New<Array>();
          p = aptr;
          len = *p;
          if (p + len + 1 > aptr + dlen)
            return NULL;
          status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          strings->Set(strings->Length(), Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          p += len;
          len = *p;
          if (p + len + 1 > aptr + dlen)
            return NULL;
          status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          strings->Set(strings->Length(), Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          record->Set(Nan::New("data").ToLocalChecked(), strings);
          break;
        }

        case ns_t_minfo: //T_MINFO:
        {
          /* The RR data is two domain names. */
          Local<Array> strings = Nan::New<Array>();
          p = aptr;
          status = ares_expand_name(p, abuf, alen, &name.as_char, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          strings->Set(strings->Length(), Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          p += len;
          status = ares_expand_name(p, abuf, alen, &name.as_char, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          strings->Set(strings->Length(), Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          record->Set(Nan::New("data").ToLocalChecked(), strings);
          break;
        }

        case ns_t_mx: //T_MX:
          /* The RR data is two bytes giving a preference ordering, and
           * then a domain name.
           */
          if (dlen < 2)
            return NULL;
          record->Set(Nan::New("priority").ToLocalChecked(),
                      Nan::New<Integer>((int)DNS__16BIT(aptr)));
          status = ares_expand_name(aptr + 2, abuf, alen, &name.as_char, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          record->Set(Nan::New("exchange").ToLocalChecked(),
                      Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          break;

        case ns_t_soa: //T_SOA:
          /* The RR data is two domain names and then five four-byte
           * numbers giving the serial number and some timeouts.
           */
          p = aptr;
          status = ares_expand_name(p, abuf, alen, &name.as_char, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          record->Set(Nan::New("primary").ToLocalChecked(),
                      Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          p += len;
          status = ares_expand_name(p, abuf, alen, &name.as_char, &len);
          if (status != ARES_SUCCESS)
            return NULL;

          record->Set(Nan::New("admin").ToLocalChecked(),
                      Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          p += len;
          if (p + 20 > aptr + dlen)
            return NULL;

          record->Set(Nan::New("serial").ToLocalChecked(),
                      Nan::New<Integer>(DNS__32BIT(p)));
          record->Set(Nan::New("refresh").ToLocalChecked(),
                      Nan::New<Integer>(DNS__32BIT(p+4)));
          record->Set(Nan::New("retry").ToLocalChecked(),
                      Nan::New<Integer>(DNS__32BIT(p+8)));
          record->Set(Nan::New("expiration").ToLocalChecked(),
                      Nan::New<Integer>(DNS__32BIT(p+12)));
          record->Set(Nan::New("minimum").ToLocalChecked(),
                      Nan::New<Integer>(DNS__32BIT(p+16)));
          break;

        case ns_t_txt: //T_TXT:
        {
          /* The RR data is one or more length-counted character
           * strings. */
          p = aptr;
          Local<Array> txts = Nan::New<Array>();
          while (p < aptr + dlen)
          {
            len = *p;
            if (p + len + 1 > aptr + dlen)
              return NULL;
            status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);
            if (status != ARES_SUCCESS)
              return NULL;
            txts->Set(txts->Length(), Nan::New(name.as_char).ToLocalChecked());
            ares_free_string(name.as_char);
            p += len;
          }
          record->Set(Nan::New("data").ToLocalChecked(), txts);
          break;
        }

        case ns_t_a: //T_A:
          /* The RR data is a four-byte Internet address. */
          if (dlen != 4)
            return NULL;
          uv_inet_ntop(AF_INET, aptr, addr, sizeof(addr));
          record->Set(Nan::New("address").ToLocalChecked(), Nan::New(addr).ToLocalChecked());
          break;

        case ns_t_aaaa: //T_AAAA:
          /* The RR data is a 16-byte IPv6 address. */
          if (dlen != 16)
            return NULL;
          uv_inet_ntop(AF_INET6, aptr, addr, sizeof(addr));
          record->Set(Nan::New("address").ToLocalChecked(), Nan::New(addr).ToLocalChecked());
          break;
        case ns_t_wks: //T_WKS:
          /* Not implemented yet */
          break;

        case ns_t_srv: //T_SRV:
          /* The RR data is three two-byte numbers representing the
           * priority, weight, and port, followed by a domain name.
           */

          record->Set(Nan::New("priority").ToLocalChecked(),
                      Nan::New<Integer>((int)DNS__16BIT(aptr)));
          record->Set(Nan::New("weight").ToLocalChecked(),
                      Nan::New<Integer>((int)DNS__16BIT(aptr + 2)));
          record->Set(Nan::New("port").ToLocalChecked(),
                      Nan::New<Integer>((int)DNS__16BIT(aptr + 4)));


          status = ares_expand_name(aptr + 6, abuf, alen, &name.as_char, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          record->Set(Nan::New("target").ToLocalChecked(),
                      Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          break;

        case ns_t_naptr://T_NAPTR:

          record->Set(Nan::New("order").ToLocalChecked(),
                      Nan::New<Integer>((int)DNS__16BIT(aptr)));
          record->Set(Nan::New("preference").ToLocalChecked(),
                      Nan::New<Integer>((int)DNS__16BIT(aptr + 2)));

          p = aptr + 4;
          status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);
          if (status != ARES_SUCCESS)
            return NULL;

          record->Set(Nan::New("flags").ToLocalChecked(),
                      Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          p += len;

          status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          record->Set(Nan::New("service").ToLocalChecked(),
                      Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          p += len;

          status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          record->Set(Nan::New("regexp").ToLocalChecked(),
                      Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          p += len;

          status = ares_expand_name(p, abuf, alen, &name.as_char, &len);
          if (status != ARES_SUCCESS)
            return NULL;
          record->Set(Nan::New("replacement").ToLocalChecked(),
                      Nan::New(name.as_char).ToLocalChecked());
          ares_free_string(name.as_char);
          break;

          //                case T_DS:
          //                case T_SSHFP:
          //                case T_RRSIG:
          //                case T_NSEC:
          //                case T_DNSKEY:
          //                    printf("\t[RR type parsing unavailable]");
          //                    break;

        default:
          printf("\t[Unknown RR; cannot parse]");
          break;
      }
      records->Set(records->Length(), record);

      return aptr + dlen;
    }


    static Local<Array> HostentToAddresses(struct hostent* host) {
      Local<Array> addresses = Nan::New<Array>();

      char ip[INET6_ADDRSTRLEN];
      for (int i = 0; host->h_addr_list[i]; ++i) {
        wrap_uv_inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));

        Local<String> address = Nan::New(ip).ToLocalChecked();
        addresses->Set(Nan::New<Integer>(i), address);
      }

      return addresses;
    }

    static Local<Array> HostentToNames(struct hostent* host) {
      Nan::EscapableHandleScope scope;
      Local<Array> names = Nan::New<Array>();

      for (uint32_t i = 0; host->h_aliases[i] != NULL; ++i) {
        Local<String> address = Nan::New(host->h_aliases[i]).ToLocalChecked();
        names->Set(i, address);
      }

      return scope.Escape(names);
    }


    class QueryWrap {
    public:
      QueryWrap(ares_channel _ares_channel) {
        Nan::HandleScope scope;
        this->_ares_channel = _ares_channel;

        Local<Object> obj = Nan::New<Object>();
        object_.Reset(obj);
      }

      virtual ~QueryWrap() {
        Nan::HandleScope scope;
        assert(!object_.IsEmpty());

        Local<Object> obj = Nan::New(object_);

        obj->Delete(Nan::New(oncomplete_sym));

        object_.Reset();
        obj.Clear();
      }

      Handle<Object> GetObject() {
        return Nan::New(object_);
      }

      void SetOptions(Handle<Value> options) {
      }

      void SetOnComplete(Handle<Value> oncomplete) {
        assert(oncomplete->IsFunction());
        Local<Object> obj = Nan::New(object_);
        obj->Set(Nan::New(oncomplete_sym), oncomplete);
      }

      void CallOnComplete(Local<Value> answer) {
        Nan::HandleScope scope;
        Local<Value> argv[2] = { Nan::New<Integer>(0), answer };
        Nan::MakeCallback(Nan::New(object_), Nan::New(oncomplete_sym), ARRAY_SIZE(argv), argv);
      }

      void CallOnComplete(Local<Value> answer, Local<Value> family) {
        Nan::HandleScope scope;
        Local<Value> argv[] = {
          Nan::New<Integer>(0),
          answer,
          family
        };
        Nan::MakeCallback(Nan::New(object_), Nan::New(oncomplete_sym), ARRAY_SIZE(argv), argv);
      }

      // Subclasses should implement the appropriate Send method.
      virtual int Send(const char* name) {
        assert(0);
        return 0;
      };

      // Subclasses should implement the appropriate Parse method.
      virtual void Parse(unsigned char* buf, int len) {
        assert(0);
      };

      virtual void Parse(struct hostent* host) {
        assert(0);
      };

      void ParseError(int status) {
        assert(status != ARES_SUCCESS);

        Nan::HandleScope scope;
        Local<Object> obj = Nan::New<Object>();
        obj->Set(Nan::New("status").ToLocalChecked(), Nan::New<Integer>(status));
        obj->Set(Nan::New("errorno").ToLocalChecked(), Nan::New(AresErrnoString(status)).ToLocalChecked());
        obj->Set(Nan::New("message").ToLocalChecked(), Nan::New(ares_strerror(status)).ToLocalChecked());
        Local<Value> argv[1] = { obj };
        Nan::MakeCallback(Nan::New(object_), Nan::New(oncomplete_sym), ARRAY_SIZE(argv), argv);
      }

    protected:
      ares_channel _ares_channel;
      void* GetQueryArg() {
        return static_cast<void*>(this);
      }

    private:
      Nan::Persistent<Object> object_;
    };


    class QueryGenericWrap: public QueryWrap {
    private:
      unsigned int dnsclass;
      unsigned int type;

    public:
      QueryGenericWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      void SetOptions(Handle<Value> options) {
        if (options->IsObject()) {
          Local<Object> options_obj = options->ToObject();
          Local<Value> classobj = options_obj->Get(Nan::New("class").ToLocalChecked());
          if (classobj->IsNumber()) {
            dnsclass = (int)classobj->Int32Value();
          } else {
            dnsclass = ns_c_in;
          }

          Local<Value> typeobj = options_obj->Get(Nan::New("type").ToLocalChecked());
          if (typeobj->IsNumber()) {
            type = (int)typeobj->Int32Value();
          } else {
            type = ns_t_a;
          }
        }
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel, name, dnsclass, type, GenericQueryCallback, GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;

        Local<Object> response = Nan::New<Object>();

        Local<Object> header = Nan::New<Object>();
        header->Set(Nan::New("id").ToLocalChecked(), Nan::New<Integer>(DNS_HEADER_QID(buf)));
        header->Set(Nan::New("qr").ToLocalChecked(), Nan::New<Integer>(DNS_HEADER_QR(buf)));
        header->Set(Nan::New("opcode").ToLocalChecked(), Nan::New<Integer>(DNS_HEADER_OPCODE(buf)));
        header->Set(Nan::New("aa").ToLocalChecked(), Nan::New<Integer>(DNS_HEADER_AA(buf)));
        header->Set(Nan::New("tc").ToLocalChecked(), Nan::New<Integer>(DNS_HEADER_TC(buf)));
        header->Set(Nan::New("rd").ToLocalChecked(), Nan::New<Integer>(DNS_HEADER_RD(buf)));
        header->Set(Nan::New("ra").ToLocalChecked(), Nan::New<Integer>(DNS_HEADER_RA(buf)));
        header->Set(Nan::New("rcode").ToLocalChecked(), Nan::New<Integer>(DNS_HEADER_RCODE(buf)));
        response->Set(Nan::New("header").ToLocalChecked(), header);

        unsigned int qdcount, ancount, nscount, arcount, i;
        const unsigned char *aptr;

        qdcount = DNS_HEADER_QDCOUNT(buf);
        ancount = DNS_HEADER_ANCOUNT(buf);
        nscount = DNS_HEADER_NSCOUNT(buf);
        arcount = DNS_HEADER_ARCOUNT(buf);

        /* Parse the questions. */
        Local<Array> questions = Nan::New<Array>();
        response->Set(Nan::New("question").ToLocalChecked(), questions);
        aptr = buf + NS_HFIXEDSZ;
        for (i = 0; i < qdcount; i++)
        {
          aptr = fill_question(aptr, buf, len, questions);
          //TODO: Handle
          //if (aptr == NULL)
          //    return;
        }

        /* Parse the answers. */
        Local<Array> answers = Nan::New<Array>();
        response->Set(Nan::New("answer").ToLocalChecked(), answers);
        for (i = 0; i < ancount; i++)
        {
          aptr = fill_rr(aptr, buf, len, answers);
          //TODO: Handle
          //if (aptr == NULL)
          //    return;
        }

        /* Parse the NS records. */
        Local<Array> authorities = Nan::New<Array>();
        response->Set(Nan::New("authority").ToLocalChecked(), authorities);
        for (i = 0; i < nscount; i++)
        {
          aptr = fill_rr(aptr, buf, len, authorities);
          //TODO: Handle
          //if (aptr == NULL)
          //    return;
        }

        /* Parse the additional records. */
        Local<Array> additionals = Nan::New<Array>();
        response->Set(Nan::New("additional").ToLocalChecked(), additionals);
        for (i = 0; i < arcount; i++)
        {
          aptr = fill_rr(aptr, buf, len, additionals);
          //TODO: Handle
          //if (aptr == NULL)
          //    return;
        }

        this->CallOnComplete(response);
      }
    };


    class QueryAWrap: public QueryWrap {
    public:
      QueryAWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel, name, ns_c_in, ns_t_a, Callback, GetQueryArg());
        return 0;
      }

      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;

        struct hostent* host;

        int status = ares_parse_a_reply(buf, len, &host, NULL, NULL);
        if (status != ARES_SUCCESS) {
          this->ParseError(status);
          return;
        }

        Local<Array> addresses = HostentToAddresses(host);
        ares_free_hostent(host);

        this->CallOnComplete(addresses);
      }
    };


    class QueryAaaaWrap: public QueryWrap {
    public:
      QueryAaaaWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_aaaa,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;

        struct hostent* host;

        int status = ares_parse_aaaa_reply(buf, len, &host, NULL, NULL);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> addresses = HostentToAddresses(host);
        ares_free_hostent(host);

        this->CallOnComplete(addresses);
      }
    };


    class QueryCnameWrap: public QueryWrap {
    public:
      QueryCnameWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_cname,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;
        struct hostent* host;

        int status = ares_parse_a_reply(buf, len, &host, NULL, NULL);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        // A cname lookup always returns a single record but we follow the
        // common API here.
        Local<Array> result = Nan::New<Array>(1);
        result->Set(0, Nan::New(host->h_name).ToLocalChecked());
        ares_free_hostent(host);

        this->CallOnComplete(result);
      }
    };


    class QueryMxWrap: public QueryWrap {
    public:
      QueryMxWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_mx,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;

        struct ares_mx_reply* mx_start;
        int status = ares_parse_mx_reply(buf, len, &mx_start);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> mx_records = Nan::New<Array>();
        Local<String> exchange_symbol = Nan::New("exchange").ToLocalChecked();
        Local<String> priority_symbol = Nan::New("priority").ToLocalChecked();

        ares_mx_reply* current = mx_start;
        for (uint32_t i = 0; current != NULL; ++i, current = current->next) {
          Local<Object> mx_record = Nan::New<Object>();
          mx_record->Set(exchange_symbol,
                         Nan::New(current->host).ToLocalChecked());
          mx_record->Set(priority_symbol,
                         Nan::New<Integer>(current->priority));
          mx_records->Set(i, mx_record);
        }

        ares_free_data(mx_start);

        this->CallOnComplete(mx_records);
      }
    };


    class QueryNsWrap: public QueryWrap {
    public:
      QueryNsWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_ns,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;
        struct hostent* host;

        int status = ares_parse_ns_reply(buf, len, &host);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> names = HostentToNames(host);
        ares_free_hostent(host);

        this->CallOnComplete(names);
      }
    };


    class QueryTxtWrap: public QueryWrap {
    public:
      QueryTxtWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_txt,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;
        struct ares_txt_reply* txt_out;

        int status = ares_parse_txt_reply(buf, len, &txt_out);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> txt_records = Nan::New<Array>();
        Local<Array> txt_chunk;

        ares_txt_reply* current = txt_out;
        uint32_t i = 0;
        for (uint32_t j = 0; current != NULL; current = current->next) {
          Local<String> txt = Nan::New(current->txt).As<String>();
          // New record found - write out the current chunk
          if (current->record_start) {
            if (!txt_chunk.IsEmpty())
              txt_records->Set(i++, txt_chunk);
            txt_chunk = Nan::New<Array>();
            j = 0;
          }
          txt_chunk->Set(j++, txt);
        }
        // Push last chunk
        txt_records->Set(i, txt_chunk);

        ares_free_data(txt_out);

        this->CallOnComplete(txt_records);
      }
    };


    class QuerySrvWrap: public QueryWrap {
    public:
      explicit QuerySrvWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_srv,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;

        struct ares_srv_reply* srv_start;
        int status = ares_parse_srv_reply(buf, len, &srv_start);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> srv_records = Nan::New<Array>();
        Local<String> name_symbol = Nan::New("name").ToLocalChecked();
        Local<String> port_symbol = Nan::New("port").ToLocalChecked();
        Local<String> priority_symbol = Nan::New("priority").ToLocalChecked();
        Local<String> weight_symbol = Nan::New("weight").ToLocalChecked();

        ares_srv_reply* current = srv_start;
        for (uint32_t i = 0; current != NULL; ++i, current = current->next) {
          Local<Object> srv_record = Nan::New<Object>();
          srv_record->Set(name_symbol,
                          Nan::New(current->host).ToLocalChecked());
          srv_record->Set(port_symbol,
                          Nan::New<Integer>(current->port));
          srv_record->Set(priority_symbol,
                          Nan::New<Integer>(current->priority));
          srv_record->Set(weight_symbol,
                          Nan::New<Integer>(current->weight));
          srv_records->Set(i, srv_record);
        }

        ares_free_data(srv_start);

        this->CallOnComplete(srv_records);
      }
    };


    class QueryNaptrWrap: public QueryWrap {
    public:
      explicit QueryNaptrWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_naptr,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;

        ares_naptr_reply* naptr_start;
        int status = ares_parse_naptr_reply(buf, len, &naptr_start);

        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> naptr_records = Nan::New<Array>();
        Local<String> flags_symbol = Nan::New("flags").ToLocalChecked();
        Local<String> service_symbol = Nan::New("service").ToLocalChecked();
        Local<String> regexp_symbol = Nan::New("regexp").ToLocalChecked();
        Local<String> replacement_symbol = Nan::New("replacement").ToLocalChecked();
        Local<String> order_symbol = Nan::New("order").ToLocalChecked();
        Local<String> preference_symbol = Nan::New("preference").ToLocalChecked();

        ares_naptr_reply* current = naptr_start;
        for (uint32_t i = 0; current != NULL; ++i, current = current->next) {
          Local<Object> naptr_record = Nan::New<Object>();
          naptr_record->Set(flags_symbol,
                            Nan::New(current->flags));
          naptr_record->Set(service_symbol,
                            Nan::New(current->service));
          naptr_record->Set(regexp_symbol,
                            Nan::New(current->regexp));
          naptr_record->Set(replacement_symbol,
                            Nan::New(current->replacement).ToLocalChecked());
          naptr_record->Set(order_symbol,
                            Nan::New<Integer>(current->order));
          naptr_record->Set(preference_symbol,
                            Nan::New<Integer>(current->preference));
          naptr_records->Set(i, naptr_record);
        }

        ares_free_data(naptr_start);

        this->CallOnComplete(naptr_records);
      }
    };


    class QuerySoaWrap: public QueryWrap {
    public:
      QuerySoaWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_soa,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) override {
        Nan::HandleScope scope;

        ares_soa_reply* soa_out;
        int status = ares_parse_soa_reply(buf, len, &soa_out);

        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Object> soa_record = Nan::New<Object>();

        soa_record->Set(Nan::New("nsname").ToLocalChecked(),
                        Nan::New(soa_out->nsname).ToLocalChecked());
        soa_record->Set(Nan::New("hostmaster").ToLocalChecked(),
                        Nan::New(soa_out->hostmaster).ToLocalChecked());
        soa_record->Set(Nan::New("serial").ToLocalChecked(),
                        Nan::New<Integer>(soa_out->serial));
        soa_record->Set(Nan::New("refresh").ToLocalChecked(),
                        Nan::New<Integer>(soa_out->refresh));
        soa_record->Set(Nan::New("retry").ToLocalChecked(),
                        Nan::New<Integer>(soa_out->retry));
        soa_record->Set(Nan::New("expire").ToLocalChecked(),
                        Nan::New<Integer>(soa_out->expire));
        soa_record->Set(Nan::New("minttl").ToLocalChecked(),
                        Nan::New<Integer>(soa_out->minttl));

        ares_free_data(soa_out);

        this->CallOnComplete(soa_record);
      }
    };


    class GetHostByAddrWrap: public QueryWrap {
    public:
      explicit GetHostByAddrWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) override {
        int length, family;
        char address_buffer[sizeof(struct in6_addr)];

        if (wrap_uv_inet_pton(AF_INET, name, &address_buffer) == 0) {
          length = sizeof(struct in_addr);
          family = AF_INET;
        } else if (wrap_uv_inet_pton(AF_INET6, name, &address_buffer) == 0) {
          length = sizeof(struct in6_addr);
          family = AF_INET6;
        } else {
          return UV_EINVAL;  // So errnoException() reports a proper error.
        }

        ares_gethostbyaddr(this->_ares_channel,
                           address_buffer,
                           length,
                           family,
                           Callback,
                           GetQueryArg());
        return 0;
      }

    protected:
      void Parse(struct hostent* host) override {
        Nan::HandleScope scope;
        this->CallOnComplete(HostentToNames(host));
      }
    };


    class GetHostByNameWrap: public QueryWrap {
    public:
      explicit GetHostByNameWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
        family=AF_UNSPEC;
      }

      void SetOptions(Handle<Value> options) {
        if (options->IsObject()) {
          family = options->ToObject()->Get(Nan::New("family").ToLocalChecked())->Int32Value();
        }
      }

      int Send(const char* name) override {
        ares_gethostbyname(this->_ares_channel,
                           name,
                           family,
                           Callback,
                           GetQueryArg());
        return 0;
      }

    protected:
      void Parse(struct hostent* host) override {
        Nan::HandleScope scope;

        Local<Array> addresses = HostentToAddresses(host);
        Local<Integer> family = Nan::New<Integer>(host->h_addrtype);

        this->CallOnComplete(addresses, family);
      }
    private:
      int family;
    };


    static void Callback(void *arg, int status, int timeouts,
                         unsigned char* answer_buf, int answer_len) {
      QueryWrap* wrap = static_cast<QueryWrap*>(arg);
      if (status != ARES_SUCCESS) {
        wrap->ParseError(status);
      } else {
        wrap->Parse(answer_buf, answer_len);
      }
      delete wrap;
    }

    //For generic query this callback will be called to handle status ARES_ENODATA.
    static void GenericQueryCallback(void *arg, int status, int timeouts,
                         unsigned char* answer_buf, int answer_len) {
      QueryWrap* wrap = (QueryWrap*)arg;

      if (status != ARES_SUCCESS && status != ARES_ENODATA) {
        wrap->ParseError(status);
      } else {
        wrap->Parse(answer_buf, answer_len);
      }

      delete wrap;
    }

    static void Callback(void *arg, int status, int timeouts,
                         struct hostent* host) {
      QueryWrap* wrap = static_cast<QueryWrap*>(arg);

      if (status != ARES_SUCCESS) {
        wrap->ParseError(status);
      } else {
        wrap->Parse(host);
      }

      delete wrap;
    }


    template <class Wrap>
    NAN_METHOD(Query) {

      Resolver* resolver = ObjectWrap::Unwrap<Resolver>(info.Holder());

      assert(!info.IsConstructCall());
      assert(info[0]->IsString());
      assert(info[2]->IsFunction());

      //Local<Object> req_wrap_obj = args[0].As<Object>();
      Wrap* wrap = new Wrap(resolver->_ares_channel);
      wrap->SetOptions(info[1]);
      wrap->SetOnComplete(info[2]);

      // We must cache the wrap's js object here, because cares might make the
      // callback from the wrap->Send stack. This will destroy the wrap's internal
      // object reference, causing wrap->GetObject() to return undefined.
      //TODO: Local<Object> object = NanNew(wrap->GetObject());

      String::Utf8Value name(info[0]);

      int r = wrap->Send(*name);
      if (r) {
        delete wrap;
      }

      info.GetReturnValue().Set(Nan::New<Integer>(r));

    }


    NAN_METHOD(GetServers) {

      Local<Array> server_array = Nan::New<Array>();

      ares_addr_node* servers;

      Resolver* resolver = ObjectWrap::Unwrap<Resolver>(info.Holder());

      int r = ares_get_servers(resolver->_ares_channel, &servers);
      assert(r == ARES_SUCCESS);

      ares_addr_node* cur = servers;

      for (uint32_t i = 0; cur != NULL; ++i, cur = cur->next) {
        char ip[INET6_ADDRSTRLEN];

        const void* caddr = static_cast<const void*>(&cur->addr);
        int err = wrap_uv_inet_ntop(cur->family, caddr, ip, sizeof(ip));
        assert(err == 0);

        Local<String> addr = Nan::New(ip).ToLocalChecked();
        server_array->Set(i, addr);
      }

      ares_free_data(servers);

      info.GetReturnValue().Set(server_array);
    }


    NAN_METHOD(SetServers) {

      assert(info[0]->IsArray());

      Local<Array> arr = Local<Array>::Cast(info[0]);

      uint32_t len = arr->Length();

      Resolver* resolver = ObjectWrap::Unwrap<Resolver>(info.Holder());

      if (len == 0) {
        int rv = ares_set_servers(resolver->_ares_channel, NULL);
        info.GetReturnValue().Set(Nan::New<Integer>(rv));
      }

      ares_addr_node* servers = new ares_addr_node[len];
      ares_addr_node* last = NULL;

      int err = 0;

      for (uint32_t i = 0; i < len; i++) {
        assert(arr->Get(i)->IsArray());

        Local<Array> elm = Local<Array>::Cast(arr->Get(i));

        assert(elm->Get(0)->Int32Value());
        assert(elm->Get(1)->IsString());

        int fam = elm->Get(0)->Int32Value();
        Nan::Utf8String ip(elm->Get(1));

        ares_addr_node* cur = &servers[i];

        switch (fam) {
          case 4:
            cur->family = AF_INET;
            err = wrap_uv_inet_pton(AF_INET, *ip, &cur->addr);
            break;
          case 6:
            cur->family = AF_INET6;
            err = wrap_uv_inet_pton(AF_INET6, *ip, &cur->addr);
            break;
          default:
            assert(0 && "Bad address family.");
            abort();
        }

        if (err)
          break;

        cur->next = NULL;

        if (last != NULL)
          last->next = cur;

        last = cur;
      }

      if (err == ARES_SUCCESS)
        err = ares_set_servers(resolver->_ares_channel, &servers[0]);
      else
        err = ARES_EBADSTR;

      delete[] servers;

      if (err == ARES_SUCCESS) {
        info.GetReturnValue().SetNull();
      } else {
        Local<Object> obj = Nan::New<Object>();
        obj->Set(Nan::New("status").ToLocalChecked(), Nan::New<Integer>(err));
        obj->Set(Nan::New("errorno").ToLocalChecked(), Nan::New(AresErrnoString(err)).ToLocalChecked());
        obj->Set(Nan::New("message").ToLocalChecked(), Nan::New(ares_strerror(err)).ToLocalChecked());
        info.GetReturnValue().Set(obj);
      }
    }


    NAN_METHOD(Resolver::New) {
      // This constructor should not be exposed to public javascript.
      // Therefore we assert that we are not trying to call this as a
      // normal function.
      Nan::HandleScope scope;
      assert(info.IsConstructCall());
      Resolver *resolver = new Resolver(info[0]->ToObject());
      resolver->Wrap(info.This());
      info.GetReturnValue().Set(info.This());
    }


    void Resolver::Initialize(Handle<Object> target) {
      Local<FunctionTemplate> constructor = Nan::New<FunctionTemplate>(New);
      constructor->InstanceTemplate()->SetInternalFieldCount(1);
      constructor->SetClassName(Nan::New("Resolver").ToLocalChecked());

      Nan::SetPrototypeMethod(constructor, "queryGeneric", Query<QueryGenericWrap>);
      Nan::SetPrototypeMethod(constructor, "queryA", Query<QueryAWrap>);
      Nan::SetPrototypeMethod(constructor, "queryAaaa", Query<QueryAaaaWrap>);
      Nan::SetPrototypeMethod(constructor, "queryCname", Query<QueryCnameWrap>);
      Nan::SetPrototypeMethod(constructor, "queryMx", Query<QueryMxWrap>);
      Nan::SetPrototypeMethod(constructor, "queryNs", Query<QueryNsWrap>);
      Nan::SetPrototypeMethod(constructor, "queryTxt", Query<QueryTxtWrap>);
      Nan::SetPrototypeMethod(constructor, "querySrv", Query<QuerySrvWrap>);
      Nan::SetPrototypeMethod(constructor, "queryNaptr", Query<QueryNaptrWrap>);
      Nan::SetPrototypeMethod(constructor, "querySoa", Query<QuerySoaWrap>);
      Nan::SetPrototypeMethod(constructor, "getHostByAddr", Query<GetHostByAddrWrap>);
      Nan::SetPrototypeMethod(constructor, "getHostByName", Query<GetHostByNameWrap>);

      Nan::SetPrototypeMethod(constructor, "getServers", GetServers);
      Nan::SetPrototypeMethod(constructor, "setServers", SetServers);

      target->Set(Nan::New("Resolver").ToLocalChecked(), constructor->GetFunction());
    };


    static void Initialize(Handle<Object> target) {

      int r = ares_library_init(ARES_LIB_INIT_ALL);
      assert(r == ARES_SUCCESS);

      target->Set(Nan::New("AF_INET").ToLocalChecked(), Nan::New<Integer>(AF_INET));
      target->Set(Nan::New("AF_INET6").ToLocalChecked(), Nan::New<Integer>(AF_INET6));
      target->Set(Nan::New("AF_UNSPEC").ToLocalChecked(), Nan::New<Integer>(AF_UNSPEC));
      target->Set(Nan::New("AI_ADDRCONFIG").ToLocalChecked(), Nan::New<Integer>(AI_ADDRCONFIG));
      target->Set(Nan::New("AI_V4MAPPED").ToLocalChecked(), Nan::New<Integer>(AI_V4MAPPED));

      target->Set(Nan::New("ARES_FLAG_USEVC").ToLocalChecked(), Nan::New<Integer>(ARES_FLAG_USEVC));
      target->Set(Nan::New("ARES_FLAG_PRIMARY").ToLocalChecked(), Nan::New<Integer>(ARES_FLAG_PRIMARY));
      target->Set(Nan::New("ARES_FLAG_IGNTC").ToLocalChecked(), Nan::New<Integer>(ARES_FLAG_IGNTC));
      target->Set(Nan::New("ARES_FLAG_NORECURSE").ToLocalChecked(), Nan::New<Integer>(ARES_FLAG_NORECURSE));
      target->Set(Nan::New("ARES_FLAG_STAYOPEN").ToLocalChecked(), Nan::New<Integer>(ARES_FLAG_STAYOPEN));
      target->Set(Nan::New("ARES_FLAG_NOSEARCH").ToLocalChecked(), Nan::New<Integer>(ARES_FLAG_NOSEARCH));
      target->Set(Nan::New("ARES_FLAG_NOALIASES").ToLocalChecked(), Nan::New<Integer>(ARES_FLAG_NOALIASES));

      oncomplete_sym.Reset(Nan::New("oncomplete").ToLocalChecked());

      Resolver::Initialize(target);

    }

  }

}


NODE_MODULE(cares_wrap, Nan::cares_wrap::Initialize)
