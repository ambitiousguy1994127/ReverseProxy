
#ifndef BUF_BLOCK_SIZE
#define BUF_BLOCK_SIZE (4*1024)
#endif

/* stop fast growing after this limit (8Mb). Will slowdown but not eat a lot of memory for big responses  */
#ifndef BUF_BLOCK_UPPER_LIMIT
#define BUF_BLOCK_UPPER_LIMIT (8ul*1024*1024*1024)
#endif

typedef struct {
    apr_pool_t* pool;
    char*       response_data;
    size_t      response_size;
    size_t      response_capacity;
} curl_recv_context_rec;

size_t curl_recv_data(void *buffer, size_t size, size_t nmemb, void *userdata);
