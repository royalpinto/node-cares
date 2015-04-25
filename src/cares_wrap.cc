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
#include "ares.h"
#include "node.h"
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


namespace node {

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

    static Persistent<String> oncomplete_sym;

    class Resolver;

    static void Callback(void *arg, int status, int timeouts,
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

    static RB_HEAD(ares_task_list, ares_task_t) ares_tasks;


    static int cmp_ares_tasks(const ares_task_t* a, const ares_task_t* b) {
      if (a->sock < b->sock) return -1;
      if (a->sock > b->sock) return 1;
      return 0;
    }


    RB_GENERATE_STATIC(ares_task_list, ares_task_t, node, cmp_ares_tasks)

    static void ares_sockstate_cb(void* data, ares_socket_t sock, int read, int write);

    class Resolver: public node::ObjectWrap {
    public:
      static void Initialize(Handle<Object> target);

      inline ares_task_list* cares_task_list() {
        return &_ares_task_list;
      }

      inline uv_timer_t* cares_timer_handle() {
        return &ares_timer;
      }

      ares_channel _ares_channel;

    private:
      static NAN_METHOD(New);

      Resolver()
      : ObjectWrap() {
        int r;

        RB_INIT(&_ares_task_list);

        struct ares_options options;
        memset(&options, 0, sizeof(options));
        options.flags = ARES_FLAG_NOCHECKRESP;
        options.sock_state_cb = ares_sockstate_cb;
        options.sock_state_cb_data = this;

        /* We do the call to ares_init_option for caller. */
        r = ares_init_options(&_ares_channel,
                              &options,
                              ARES_OPT_FLAGS | ARES_OPT_SOCK_STATE_CB);
        assert(r == ARES_SUCCESS);

        /* Initialize the timeout timer. The timer won't be started until the */
        /* first socket is opened. */

        uv_timer_init(uv_default_loop(), &ares_timer);
      }

      ~Resolver() {
      }

      ares_task_list _ares_task_list;
      uv_timer_t ares_timer;
    };


    /* This is called once per second by loop->timer. It is used to constantly */
    /* call back into c-ares for possibly processing timeouts. */
    static void ares_timeout(uv_timer_t* handle) {
      Resolver *resolver = (Resolver*)handle->data;
      assert(!RB_EMPTY(&ares_tasks));
      ares_process_fd(resolver->_ares_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }

    /* This is called once per second by loop->timer. It is used to constantly */
    /* call back into c-ares for possibly processing timeouts. */
    /* This is an old version of uv_timer_cb. keeping it to support backward compatibility. */
    static void ares_timeout(uv_timer_t* handle, int status) {
      ares_timeout(handle);
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
      task = RB_FIND(ares_task_list, &ares_tasks, &lookup_task);

      if (read || write) {
        if (!task) {
          /* New socket */

          /* If this is the first socket then start the timer. */
          uv_timer_t* timer_handle = resolver->cares_timer_handle();
          if (!uv_is_active((uv_handle_t*) &timer_handle)) {
            assert(RB_EMPTY(&ares_tasks));
            uv_timer_start(timer_handle, ares_timeout, 1000, 1000);
          }

          task = ares_task_create(resolver, sock);
          if (task == NULL) {
            /* This should never happen unless we're out of memory or something */
            /* is seriously wrong. The socket won't be polled, but the the query */
            /* will eventually time out. */
            return;
          }

          RB_INSERT(ares_task_list, &ares_tasks, task);
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

        RB_REMOVE(ares_task_list, &ares_tasks, task);
        uv_close((uv_handle_t*) &task->poll_watcher, ares_poll_close_cb);

        if (RB_EMPTY(&ares_tasks)) {
          uv_timer_stop(resolver->cares_timer_handle());
        }
      }
    }


    static Local<Array> HostentToAddresses(struct hostent* host) {
      Local<Array> addresses = NanNew<Array>();

      char ip[INET6_ADDRSTRLEN];
      for (int i = 0; host->h_addr_list[i]; ++i) {
        wrap_uv_inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));

        Local<String> address = NanNew(ip);
        addresses->Set(NanNew<Integer>(i), address);
      }

      return addresses;
    }

    static Local<Array> HostentToNames(struct hostent* host) {
      NanEscapableScope();
      Local<Array> names = NanNew<Array>();

      for (uint32_t i = 0; host->h_aliases[i] != NULL; ++i) {
        Local<String> address = NanNew(host->h_aliases[i]);
        names->Set(i, address);
      }

      return NanEscapeScope(names);
    }


    class QueryWrap {
    public:
      QueryWrap(ares_channel _ares_channel) {
        NanScope();
        this->_ares_channel = _ares_channel;

        Local<Object> obj = NanNew<Object>();
        NanAssignPersistent(object_, obj);
      }

      virtual ~QueryWrap() {
        assert(!object_.IsEmpty());

        Local<Object> obj = NanNew(object_);

        obj->Delete(NanNew(oncomplete_sym));

        NanDisposePersistent(object_);
        obj.Clear();
      }

      Handle<Object> GetObject() {
        return NanNew(object_);
      }

      void SetOptions(Handle<Value> options) {
      }

      void SetOnComplete(Handle<Value> oncomplete) {
        assert(oncomplete->IsFunction());
        Local<Object> obj = NanNew(object_);
        obj->Set(NanNew(oncomplete_sym), oncomplete);
      }

      void CallOnComplete(Local<Value> answer) {
        NanScope();
        Local<Value> argv[2] = { NanNew<Integer>(0), answer };
        NanMakeCallback(NanNew(object_), NanNew(oncomplete_sym), ARRAY_SIZE(argv), argv);
      }

      void CallOnComplete(Local<Value> answer, Local<Value> family) {
        NanScope();
        Local<Value> argv[] = {
          NanNew<Integer>(0),
          answer,
          family
        };
        NanMakeCallback(NanNew(object_), NanNew(oncomplete_sym), ARRAY_SIZE(argv), argv);
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

        NanScope();
        Local<Object> obj = NanNew<Object>();
        obj->Set(NanNew("code"), NanNew<Integer>(status));
        obj->Set(NanNew("message"), NanNew(ares_strerror(status)));
        Local<Value> argv[1] = { obj };
        NanMakeCallback(NanNew(object_), NanNew(oncomplete_sym), ARRAY_SIZE(argv), argv);
      }

    protected:
      ares_channel _ares_channel;
      void* GetQueryArg() {
        return static_cast<void*>(this);
      }

    private:
      Persistent<Object> object_;
    };


    class QueryAWrap: public QueryWrap {
    public:
      QueryAWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) {
        ares_query(this->_ares_channel, name, ns_c_in, ns_t_a, Callback, GetQueryArg());
        return 0;
      }

      void Parse(unsigned char* buf, int len) {
        NanScope();

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

      int Send(const char* name) {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_aaaa,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) {
        NanScope();

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

      int Send(const char* name) {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_cname,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) {
        NanScope();
        struct hostent* host;

        int status = ares_parse_a_reply(buf, len, &host, NULL, NULL);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        // A cname lookup always returns a single record but we follow the
        // common API here.
        Local<Array> result = NanNew<Array>(1);
        result->Set(0, NanNew(host->h_name));
        ares_free_hostent(host);

        this->CallOnComplete(result);
      }
    };


    class QueryMxWrap: public QueryWrap {
    public:
      QueryMxWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_mx,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) {
        NanScope();

        struct ares_mx_reply* mx_start;
        int status = ares_parse_mx_reply(buf, len, &mx_start);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> mx_records = NanNew<Array>();
        Local<String> exchange_symbol = NanNew("exchange");
        Local<String> priority_symbol = NanNew("priority");

        ares_mx_reply* current = mx_start;
        for (uint32_t i = 0; current != NULL; ++i, current = current->next) {
          Local<Object> mx_record = NanNew<Object>();
          mx_record->Set(exchange_symbol,
                         NanNew(current->host));
          mx_record->Set(priority_symbol,
                         NanNew<Integer>(current->priority));
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

      int Send(const char* name) {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_ns,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) {
        NanScope();
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

      int Send(const char* name) {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_txt,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) {
        NanScope();
        struct ares_txt_reply* txt_out;

        int status = ares_parse_txt_reply(buf, len, &txt_out);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> txt_records = NanNew<Array>();
        Local<Array> txt_chunk;

        ares_txt_reply* current = txt_out;
        uint32_t i = 0;
        for (uint32_t j = 0; current != NULL; current = current->next) {
          Local<String> txt = NanNew(current->txt);
          // New record found - write out the current chunk
          if (current->record_start) {
            if (!txt_chunk.IsEmpty())
              txt_records->Set(i++, txt_chunk);
            txt_chunk = NanNew<Array>();
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

      int Send(const char* name) {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_srv,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) {
        NanScope();

        struct ares_srv_reply* srv_start;
        int status = ares_parse_srv_reply(buf, len, &srv_start);
        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> srv_records = NanNew<Array>();
        Local<String> name_symbol = NanNew("name");
        Local<String> port_symbol = NanNew("port");
        Local<String> priority_symbol = NanNew("priority");
        Local<String> weight_symbol = NanNew("weight");

        ares_srv_reply* current = srv_start;
        for (uint32_t i = 0; current != NULL; ++i, current = current->next) {
          Local<Object> srv_record = NanNew<Object>();
          srv_record->Set(name_symbol,
                          NanNew(current->host));
          srv_record->Set(port_symbol,
                          NanNew<Integer>(current->port));
          srv_record->Set(priority_symbol,
                          NanNew<Integer>(current->priority));
          srv_record->Set(weight_symbol,
                          NanNew<Integer>(current->weight));
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

      int Send(const char* name) {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_naptr,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) {
        NanScope();

        ares_naptr_reply* naptr_start;
        int status = ares_parse_naptr_reply(buf, len, &naptr_start);

        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Array> naptr_records = NanNew<Array>();
        Local<String> flags_symbol = NanNew("flags");
        Local<String> service_symbol = NanNew("service");
        Local<String> regexp_symbol = NanNew("regexp");
        Local<String> replacement_symbol = NanNew("replacement");
        Local<String> order_symbol = NanNew("order");
        Local<String> preference_symbol = NanNew("preference");

        ares_naptr_reply* current = naptr_start;
        for (uint32_t i = 0; current != NULL; ++i, current = current->next) {
          Local<Object> naptr_record = NanNew<Object>();
          naptr_record->Set(flags_symbol,
                            NanNew(current->flags));
          naptr_record->Set(service_symbol,
                            NanNew(current->service));
          naptr_record->Set(regexp_symbol,
                            NanNew(current->regexp));
          naptr_record->Set(replacement_symbol,
                            NanNew(current->replacement));
          naptr_record->Set(order_symbol,
                            NanNew<Integer>(current->order));
          naptr_record->Set(preference_symbol,
                            NanNew<Integer>(current->preference));
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

      int Send(const char* name) {
        ares_query(this->_ares_channel,
                   name,
                   ns_c_in,
                   ns_t_soa,
                   Callback,
                   GetQueryArg());
        return 0;
      }

    protected:
      void Parse(unsigned char* buf, int len) {
        NanScope();

        ares_soa_reply* soa_out;
        int status = ares_parse_soa_reply(buf, len, &soa_out);

        if (status != ARES_SUCCESS) {
          ParseError(status);
          return;
        }

        Local<Object> soa_record = NanNew<Object>();

        soa_record->Set(NanNew("nsname"),
                        NanNew(soa_out->nsname));
        soa_record->Set(NanNew("hostmaster"),
                        NanNew(soa_out->hostmaster));
        soa_record->Set(NanNew("serial"),
                        NanNew<Integer>(soa_out->serial));
        soa_record->Set(NanNew("refresh"),
                        NanNew<Integer>(soa_out->refresh));
        soa_record->Set(NanNew("retry"),
                        NanNew<Integer>(soa_out->retry));
        soa_record->Set(NanNew("expire"),
                        NanNew<Integer>(soa_out->expire));
        soa_record->Set(NanNew("minttl"),
                        NanNew<Integer>(soa_out->minttl));

        ares_free_data(soa_out);

        this->CallOnComplete(soa_record);
      }
    };


    class GetHostByAddrWrap: public QueryWrap {
    public:
      explicit GetHostByAddrWrap(ares_channel _ares_channel): QueryWrap(_ares_channel) {
      }

      int Send(const char* name) {
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
      void Parse(struct hostent* host) {
        NanScope();
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
          family = options->ToObject()->Get(NanNew("family"))->Int32Value();
        }
      }

      int Send(const char* name) {
        ares_gethostbyname(this->_ares_channel,
                           name,
                           family,
                           Callback,
                           GetQueryArg());
        return 0;
      }

    protected:
      void Parse(struct hostent* host) {
        NanScope();

        Local<Array> addresses = HostentToAddresses(host);
        Local<Integer> family = NanNew<Integer>(host->h_addrtype);

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
      NanScope();

      Resolver* resolver = ObjectWrap::Unwrap<Resolver>(args.Holder());

      assert(!args.IsConstructCall());
      assert(args[0]->IsString());
      assert(args[2]->IsFunction());

      //Local<Object> req_wrap_obj = args[0].As<Object>();
      Wrap* wrap = new Wrap(resolver->_ares_channel);
      wrap->SetOptions(args[1]);
      wrap->SetOnComplete(args[2]);

      // We must cache the wrap's js object here, because cares might make the
      // callback from the wrap->Send stack. This will destroy the wrap's internal
      // object reference, causing wrap->GetObject() to return undefined.
      //TODO: Local<Object> object = NanNew(wrap->GetObject());

      String::Utf8Value name(args[0]);

      int r = wrap->Send(*name);
      if (r) {
        delete wrap;
      }

      NanReturnValue(NanNew<Integer>(r));

    }


    NAN_METHOD(GetServers) {
      NanScope();

      Local<Array> server_array = NanNew<Array>();

      ares_addr_node* servers;

      Resolver* resolver = ObjectWrap::Unwrap<Resolver>(args.Holder());

      int r = ares_get_servers(resolver->_ares_channel, &servers);
      assert(r == ARES_SUCCESS);

      ares_addr_node* cur = servers;

      for (uint32_t i = 0; cur != NULL; ++i, cur = cur->next) {
        char ip[INET6_ADDRSTRLEN];

        const void* caddr = static_cast<const void*>(&cur->addr);
        int err = wrap_uv_inet_ntop(cur->family, caddr, ip, sizeof(ip));
        assert(err == 0);

        Local<String> addr = NanNew(ip);
        server_array->Set(i, addr);
      }

      ares_free_data(servers);

      NanReturnValue(server_array);
    }


    NAN_METHOD(SetServers) {
      NanScope();

      assert(args[0]->IsArray());

      Local<Array> arr = Local<Array>::Cast(args[0]);

      uint32_t len = arr->Length();

      Resolver* resolver = ObjectWrap::Unwrap<Resolver>(args.Holder());

      if (len == 0) {
        int rv = ares_set_servers(resolver->_ares_channel, NULL);
        NanReturnValue(NanNew<Integer>(rv));
      }

      ares_addr_node* servers = new ares_addr_node[len];
      ares_addr_node* last = NULL;

      int err;

      for (uint32_t i = 0; i < len; i++) {
        assert(arr->Get(i)->IsArray());

        Local<Array> elm = Local<Array>::Cast(arr->Get(i));

        assert(elm->Get(0)->Int32Value());
        assert(elm->Get(1)->IsString());

        int fam = elm->Get(0)->Int32Value();
        NanUtf8String ip(elm->Get(1));

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
        NanReturnNull();
      } else {
        Local<Object> obj = NanNew<Object>();
        obj->Set(NanNew("code"), NanNew<Integer>(err));
        obj->Set(NanNew("message"), NanNew(ares_strerror(err)));
        NanReturnValue(obj);
      }
    }


    NAN_METHOD(Resolver::New) {
      // This constructor should not be exposed to public javascript.
      // Therefore we assert that we are not trying to call this as a
      // normal function.
      NanScope();
      assert(args.IsConstructCall());
      Resolver *resolver = new Resolver();
      resolver->Wrap(args.This());
      args.GetReturnValue().Set(args.This());
    }


    void Resolver::Initialize(Handle<Object> target) {
      Local<FunctionTemplate> constructor = NanNew<FunctionTemplate>(New);
      constructor->InstanceTemplate()->SetInternalFieldCount(1);
      constructor->SetClassName(NanNew("Resolver"));

      NODE_SET_PROTOTYPE_METHOD(constructor, "queryA", Query<QueryAWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "queryAaaa", Query<QueryAaaaWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "queryCname", Query<QueryCnameWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "queryMx", Query<QueryMxWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "queryNs", Query<QueryNsWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "queryTxt", Query<QueryTxtWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "querySrv", Query<QuerySrvWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "queryNaptr", Query<QueryNaptrWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "querySoa", Query<QuerySoaWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "getHostByAddr", Query<GetHostByAddrWrap>);
      NODE_SET_PROTOTYPE_METHOD(constructor, "getHostByName", Query<GetHostByNameWrap>);

      NODE_SET_PROTOTYPE_METHOD(constructor, "getServers", GetServers);
      NODE_SET_PROTOTYPE_METHOD(constructor, "setServers", SetServers);

      target->Set(NanNew("Resolver"), constructor->GetFunction());
    };


    static void Initialize(Handle<Object> target) {

      int r = ares_library_init(ARES_LIB_INIT_ALL);
      assert(r == ARES_SUCCESS);

      target->Set(NanNew("AF_INET"), NanNew<Integer>(AF_INET));
      target->Set(NanNew("AF_INET6"), NanNew<Integer>(AF_INET6));

      NanAssignPersistent(oncomplete_sym, NanNew("oncomplete"));

      Resolver::Initialize(target);

    }

  }

}


NODE_MODULE(cares_wrap, node::cares_wrap::Initialize)
