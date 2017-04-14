#ifndef LIBDPF_B64
#define LIBDPF_B64

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

void base64_cleanup();

#endif
