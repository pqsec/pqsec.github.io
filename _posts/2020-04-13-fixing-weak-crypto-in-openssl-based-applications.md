---
layout: post
title: "Fixing weak crypto in OpenSSL based applications"
description: April 13th, 2020
excerpt: "Fixing a proprietary tool, which uses weak cryptography, and learning runtime code patching along the way."
---

# Fixing weak crypto in OpenSSL based applications

### Why crypto becomes weak

No one designs weak cryptographic algorithms on purpose. Well, almost no one - sometimes state intelligence agencies [try to backdoor crypto for their own purposes][ec-drbg-backdoor], but hopefully this is an exception and in general people have best intentions in mind.

So, why does some crypto suddenly become weak? All practical cryptographic algorithms are designed around some hard computational problems. That is, it is practically hard (but not impossible!) to efficiently execute the algorithm without knowing some secret information (the key). The basic assumptions of strong crypto are:
  * an efficient algorithm, which allows to do a specific information transformation (for example, decryption or signing) without possessing the key does not exist
  * all existing algorithms, which allow to do the above, require substantial resources (usually compute time and/or memory), which makes them impractical, because using current technology it will either require hundreds or thousands of years to crack a single byte or the whole world just does not have enough memory to accommodate the algorithm's state

A specific cryptographic algorithm becomes weak, when one of these assumptions or even both do not hold anymore. The first assumption might be broken, when some researcher invents and publishes an algorithm, which makes a hard computational problem not hard anymore: the published approach might significantly reduce compute/memory requirements to crack the protected information. For example, see why [RC4 cipher is not used in TLS anymore][rc4nomore].

The second assumption is broken naturally over time, mostly because of rapid technological advancements. Not only computers grow more powerful every day and more compute and memory resources are available, but also completely new technologies emerge, which allow to [fully break some of the modern and most secure asymmetric cryptosystems][quantum-computing] in an instant.

### Hypothetical case study

Imagine you are a security engineer at a SaaS company, which provides cloud document storage as one of its offerings. Your cloud runs a third-party proprietary software stack from some vendor. All documents in the system are indexed by their IDs, which are generated, when the document is first uploaded. Your third-party software vendor decided that the simplest way to generate this ID for a document is to just compute its **SHA-1 value**.

One day you come to the office and see chaos: the world is not the same anymore, because [SHA-1 was officially declared broken in practice][shattered-io] (and this part is real!). Your company reached out to the vendor to provide a fix, but, as often happens with vendors, they either said it would take them months or years to provide a fix or that the attack "is not applicable to the software security model". Either way your company disagrees and your job is to provide a hotfix, while the business is looking into alternatives.

### Tool analysis

We previously agreed that the third-party vendor software is proprietary, but for the purposes of this exercise (and so you can compile and run this at home) here is the source version of the hypothetical tool:

*customhash.c:*

```cpp
#include <stdio.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

static int hash(FILE *f)
{
    int err, i;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int md_size;
    
    unsigned char buf[4096], *pos;
    size_t bytes_read;

    pos = buf;
    bytes_read = fread(buf, 1, buf + sizeof(buf) - pos, f);
    while (bytes_read && pos < (buf + sizeof(buf)))
    {
        pos += bytes_read;
        bytes_read = fread(buf, 1, buf + sizeof(buf) - pos, f);
    }
    
    if (!feof(f))
    {
        errno = EIO;
        return errno;
    }
    
    if (!EVP_Digest(buf, pos - buf, md, &md_size, EVP_sha1(), NULL))
    {
        errno = EFAULT;
        return errno;
    }

    for (i = 0; i < md_size; i++)
        printf("%02x", md[i]);
    puts("");
    
    return 0;
}
int main(int argc, char **argv)
{
    int err;
    FILE *f = stdin;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror(NULL);
            return errno;
        }
    }
    
    err = hash(f);
    if (err)
        perror(NULL);

    if (argc > 1)
        fclose(f);

    return err;
}
```

So, in a nutshell, the tool just reads the contents of a file into a buffer and computes its SHA-1. Let's verify it works by comparing its output to a well-known SHA-1 implementation:

```bash
$ gcc -o customhash customhash.c -lcrypto
$ echo abc | ./customhash
03cfd743661f07975fa2f1220c5194cbaff48451
$ echo abc | sha1sum
03cfd743661f07975fa2f1220c5194cbaff48451  -
```

Works indeed. But remember: we did not compile the tool ourselves - it is proprietary. However, we can check if the tool was linked statically or dynamically and what libraries it uses in the latter case:

```bash
$ ldd ./customhash
	linux-vdso.so.1 (0x00007ffc26bea000)
	libcrypto.so.1.1 => /lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f6350798000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f63505d7000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f63505d2000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f63505b1000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f6350a94000)
```

We're in luck: it was linked dynamically and it uses [OpenSSL][openssl]. The reason we're focusing on OpenSSL in this post is because OpenSSL is a de-facto cryptographic library of choice in many applications, even proprietary ones, because of its maturity and permissive license.

### Hooking crypto with LD_PRELOAD

[`LD_PRELOAD`][ld-preload] is a powerful instrument to modify the behaviour of a dynamically linked application: it is possible to override almost any library function by defining an environment variable and writing some code. In our case we want to replace SHA-1 computation in our toy proprietary tool with more secure SHA-256. But first we need to actually know which function to "hook" (replace that is):

```bash
$ nm -D ./customhash | grep 'U '
                 U __errno_location
                 U EVP_Digest
                 U EVP_sha1
                 U fclose
                 U feof
                 U fopen
                 U fread
                 U __libc_start_main
                 U perror
                 U printf
                 U puts
```

The above command outputs all the functions our `customhash` tool uses from linked dynamic libraries ("U" stands for "uses" probably). Most functions are from `libc`, but `EVP_Digest` and `EVP_sha1` come from OpenSSL (if we google those, we get directed to the OpenSSL online man page). At this point we need to write a small dynamic library, which exports same functions with same signatures, but compute SHA-256 instead. In fact we need to replace only `EVP_Digest` as `EVP_sha1` just returns the internal OpenSSL SHA-1 algorithm ID. One potential implementation might look like below:

*cryptofix.c*

```cpp
#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)
{
    unsigned char sha256_md[SHA256_DIGEST_LENGTH];
    unsigned int sha256_md_size, err;

    static int (*real_fn)(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "EVP_Digest");
        if (!real_fn)
        {
            fputs("cannot find EVP_Digest", stderr);
            exit(1);
        }
    }
    
    if (type == EVP_sha1())
    {
        err = real_fn(data, count, sha256_md, &sha256_md_size, EVP_sha256(), impl);
        fputs("replacing SHA1 with SHA256\n", stderr);
        memcpy(md, sha256_md, SHA_DIGEST_LENGTH);
        *size = SHA_DIGEST_LENGTH;
        return err;
    }
    else
        return real_fn(data, count, md, size, type, impl);
}
```

There are couple of things to note from the above implementation: first of all, we need to get a pointer to the real OpenSSL `EVP_Digest` function, so we can forward calls to it. We obtain the address using the [`RTLD_NEXT`][libdl-man] trick from `libdl`. This is needed because `EVP_Digest` is a wrapper function, which computes any hash algorithm supported by OpenSSL. So we can't just replace it with a SHA-256 implementation, because the calling application might rely on different hash algorithms at once and use the same function for all of them. So in our implementation we "filter out" the calls, which request SHA-1 computations and pass the rest as is.

Secondly, we don't want to write a SHA-256 implementation ourselves. We already know that the application is using OpenSSL, so when our code runs, we have access to OpenSSL library in our process address space. Moreover, we already have OpenSSL `EVP_Digest` address obtained from above, so we just call OpenSSL to compute SHA-256 for us.

Finally, the output of SHA-1 is just 20 bytes, but SHA-256 produces 32 bytes. OpenSSL returns the result to the caller allocated buffer, but at this point we can't assume the calling application allocated enough memory to store the full SHA-256 result, because it is expecting a SHA-1 hash. To be safe and not introduce a buffer overflow we will strip the extra 12 bytes from the computed SHA-256 before returning the result to the caller. Some security researches may argue that truncating hash results decreases security and they will be correct. However, for this use case, it is still more secure to use a secure hash algorithm with a truncated result rather than insecure hash algorithm.

Let's check if everything works correctly:

```bash
$ gcc -shared -fPIC -o cryptofix.so ;.c
$ echo abc | LD_PRELOAD=./cryptofix.so ./customhash
replacing SHA1 with SHA256
edeaaff3f1774ad2888673770c6d64097e391bc3
$ echo abc | sha256sum
edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb  -
```

Hurray! We successfully replaced weak SHA-1 with stronger SHA-256 without touching any code in the original application.

### The vendor strikes back

While the vendor may find reasons to refuse fixing our insecure algorithm, they are obliged to fix bugs. If we examine our toy `customhash.c` tool, we may notice it has a bug: it can't compute hashes of files larger than 4096 bytes because of the static buffer in the `hash` function:

```bash
$ printf 'a%.0s' {1..4095} | ./customhash
10236568a284fb3733bd87c15280af95bd528839
$ printf 'a%.0s' {1..4096} | ./customhash
Input/output error
```

So the vendor fixes it and delivers the updated tool (because their code is nicely decoupled, they left the `main` function as is and just rewrote the `hash` function implementation with the same prototype):

*customhashv2.c:*

```cpp
...
static int hash(FILE *f)
{
    int err, i;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int md_size;
    
    unsigned char buf[256];
    size_t bytes_read;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        errno = ENOMEM;
        return errno;
    }
    
    if (!EVP_DigestInit(ctx, EVP_sha1()))
    {
        EVP_MD_CTX_free(ctx);
        errno = EFAULT;
        return errno;
    }

    bytes_read = fread(buf, 1, sizeof(buf), f);
    while (bytes_read)
    {
        if (!EVP_DigestUpdate(ctx, buf, bytes_read))
        {
            EVP_MD_CTX_free(ctx);
            errno = EFAULT;
            return errno;
        }
        bytes_read = fread(buf, 1, sizeof(buf), f);
    }
    
    if (!feof(f))
    {
        EVP_MD_CTX_free(ctx);
        errno = EIO;
        return errno;
    }
    
    if (!EVP_DigestFinal(ctx, md, &md_size))
    {
        EVP_MD_CTX_free(ctx);
        errno = EFAULT;
        return errno;
    }

    for (i = 0; i < md_size; i++)
        printf("%02x", md[i]);
    puts("");
    
    return 0;
}
...
```

Let's check if it works:

```bash
$ gcc -o customhashv2 customhashv2.c -lcrypto
$ echo abc | ./customhashv2
03cfd743661f07975fa2f1220c5194cbaff48451
$ echo abc | sha1sum
03cfd743661f07975fa2f1220c5194cbaff48451  -
$ printf 'a%.0s' {1..4096} | ./customhashv2
8c51fb6a0b587ec95ca74acfa43df7539b486297
$ printf 'a%.0s' {1..4096} | sha1sum
8c51fb6a0b587ec95ca74acfa43df7539b486297  -
```

Good! The bug is fixed, but does our hack work:

```bash
$ echo abc | LD_PRELOAD=./cryptofix.so ./customhashv2
03cfd743661f07975fa2f1220c5194cbaff48451
```

We don't see our "replacing SHA1 with SHA256" message anymore and the new tool clearly computes SHA-1. This is because the updated tool uses different functions from OpenSSL to do its job and we did not hook those:

```bash
$ nm -D ./customhashv2 | grep 'U '
                 U __errno_location
                 U EVP_DigestFinal
                 U EVP_DigestInit
                 U EVP_DigestUpdate
                 U EVP_MD_CTX_free
                 U EVP_MD_CTX_new
                 U EVP_sha1
                 U fclose
                 U feof
                 U fopen
                 U fread
                 U __libc_start_main
                 U perror
                 U printf
                 U puts
```

To support arbitrary length files the tool now uses an interface, which processes the data iteratively. But we need to update our hooking library:

*cryptofixv2.c:*

```cpp
#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
    static int (*real_fn)(EVP_MD_CTX *ctx, const EVP_MD *type) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "EVP_DigestInit");
        if (!real_fn)
        {
            fputs("cannot find EVP_DigestInit", stderr);
            exit(1);
        }
    }
    
    if (type == EVP_sha1())
        return real_fn(ctx, EVP_sha256());
    else
        return real_fn(ctx, type);
}

int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
    static int (*real_fn)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "EVP_DigestFinal");
        if (!real_fn)
        {
            fputs("cannot find EVP_DigestFinal", stderr);
            exit(1);
        }
    }

    if (EVP_MD_CTX_md(ctx) == EVP_sha256())
    {
        unsigned char sha256_md[SHA256_DIGEST_LENGTH];
        unsigned int sha256_md_size, err;
        
        err = real_fn(ctx, sha256_md, &sha256_md_size);
        fputs("replacing SHA1 with SHA256\n", stderr);
        memcpy(md, sha256_md, SHA_DIGEST_LENGTH);
        *s = SHA_DIGEST_LENGTH;
        return err;
    }
    else
        return real_fn(ctx, md, s);
}
```

Now we hook two functions:
  * as before, in `EVP_DigestInit` we detect when the caller requests SHA-1 calculation and instead request SHA-256 calculation from OpenSSL
  * in `EVP_DigestFinal` we truncate the results of any SHA-256 calculation to 20 bytes and return the results to the caller

For simplicity, this implementation assumes that the calling application never requests SHA-256 hash calculations on its own. If that's not the case, the hooking library might become more complex, as we have to track somehow (for example, in a set) the OpenSSL context objects we "patched" in `EVP_DigestInit`, so we only truncate the original-to-be SHA-1 results in the `EVP_DigestFinal`.

Checking if it works:

```bash
$ gcc -shared -fPIC -o cryptofixv2.so cryptofixv2.c
$ echo abc | LD_PRELOAD=./cryptofixv2.so ./customhashv2
replacing SHA1 with SHA256
edeaaff3f1774ad2888673770c6d64097e391bc3
$ echo abc | sha256sum
edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb  -
```

OK, we're good! Did we cover all possible cases? Here is another potential update from the vendor:

*customhashv3.c:*

```cpp
...
static int hash(FILE *f)
{
    int err, i;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int md_size = sizeof(md);
    
    unsigned char buf[256];
    int bytes_read;
    
    BIO *filebio, *sha1bio;

    filebio = BIO_new_fp(f, BIO_NOCLOSE);
    if (!filebio)
    {
        errno = ENOMEM;
        return errno;
    }
    
    sha1bio = BIO_new(BIO_f_md());
    if (!sha1bio)
    {
        BIO_free(filebio);
        errno = ENOMEM;
        return errno;
    }

    BIO_set_md(sha1bio, EVP_sha1());
    BIO_push(sha1bio, filebio);

    bytes_read = BIO_read(sha1bio, buf, sizeof(buf));
    while (bytes_read > 0)
    {
        bytes_read = BIO_read(sha1bio, buf, sizeof(buf));
    }
    
    if (bytes_read < 0)
    {
        BIO_free_all(sha1bio);
        errno = EIO;
        return errno;
    }

    if (BIO_gets(sha1bio, md, sizeof(md)) <= 0)
    {
        BIO_free_all(sha1bio);
        errno = EFAULT;
        return errno;
    }

    BIO_free_all(sha1bio);

    for (i = 0; i < md_size; i++)
        printf("%02x", md[i]);
    puts("");
    
    return 0;
}
...
```

It works as the previous one:

```bash
$ gcc -o customhashv3 customhashv3.c -lcrypto
$ echo abc | ./customhashv3
03cfd743661f07975fa2f1220c5194cbaff48451
```

But we may already guess our hooking library will not work anymore just by looking at:

```bash
$ nm -D ./customhashv3 | grep 'U '
                 U BIO_ctrl
                 U BIO_f_md
                 U BIO_free
                 U BIO_free_all
                 U BIO_gets
                 U BIO_new
                 U BIO_new_fp
                 U BIO_push
                 U BIO_read
                 U __errno_location
                 U EVP_sha1
                 U fclose
                 U fopen
                 U __libc_start_main
                 U perror
                 U printf
                 U puts
```

The calling application uses yet another set of function calls to compute the SHA-1 digest and we have to come up with a new fix:

*cryptofixv3.c:*

```cpp
#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg)
{
    static long (*real_fn)(BIO *bp, int cmd, long larg, void *parg) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "BIO_ctrl");
        if (!real_fn)
        {
            fputs("cannot find BIO_ctrl", stderr);
            exit(1);
        }
    }
    
    if (cmd == BIO_C_SET_MD && parg == EVP_sha1())
        return real_fn(bp, cmd, larg, (void *)EVP_sha256());
    else
        return real_fn(bp, cmd, larg, parg);
}

int BIO_gets(BIO *bp, char *buf, int size)
{
    EVP_MD *md = NULL;
    static int (*real_fn)(BIO *bp, char *buf, int size) = NULL;
    if (!real_fn)
    {
        real_fn = dlsym(RTLD_NEXT, "BIO_gets");
        if (!real_fn)
        {
            fputs("cannot find BIO_gets", stderr);
            exit(1);
        }
    }

    if (BIO_method_type(bp) == BIO_TYPE_MD && BIO_get_md(bp, &md))
    {
        if (md == EVP_sha256()) {
            char sha256_md[SHA256_DIGEST_LENGTH];
            int err;
    
            if (size < SHA_DIGEST_LENGTH)
                return 0;
        
            err = real_fn(bp, sha256_md, sizeof(sha256_md));
            fputs("replacing SHA1 with SHA256\n", stderr);
            memcpy(buf, sha256_md, size);
            return err;
        }
    }

    return real_fn(bp, buf, size);
}
```

It up to the reader to verify the above code works, but it is worth noting it suffers from same limitations and assumptions as `v2`.

At this point it is clear that OpenSSL has a rather diverse API and the same thing can be implemented in many different ways. This makes OpenSSL algorithm hooking hard as it is almost impossible to account for all cases and combinations.

### OpenSSL engines to the rescue

While we can't provide reliable algorithm replacement for any cryptographic library, if the application uses OpenSSL, we can do better than above with [OpenSSL engines][openssl-engine].

OpenSSL engines are third-party extensions anyone can write to provide a custom implementation of any cryptographic algorithm. They are used primarily for two cases:

  * integrating different hardware cryptographic devices into OpenSSL and OpenSSL-based applications
  * introduce new cryptographic algorithms into OpenSSL and make them available via generic OpenSSL `EVP_x` API

But we will abuse the framework a bit: we will write an "alternative" implementation of SHA-1 algorithm, which will do SHA-256 computations (the code below is based on [the example from OpenSSL blog][openssl-engine-example]):

*sha1-sha256.c:*

```cpp
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static const char *engine_id = "sha1-sha256";
static const char *engine_name =
    "An engine, which converts SHA1 to SHA256 for better security";

static int digest_init(EVP_MD_CTX *ctx) {
  return SHA256_Init(EVP_MD_CTX_md_data(ctx));
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
  return SHA256_Update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md) {
  char sha256_md[SHA256_DIGEST_LENGTH];
  int err;

  err = SHA256_Final(sha256_md, EVP_MD_CTX_md_data(ctx));
  fputs("replacing SHA1 with SHA256\n", stderr);
  memcpy(md, sha256_md, SHA_DIGEST_LENGTH);
  return err;
}

static EVP_MD *digest_meth = NULL;
static int digest_nids[] = {NID_sha1, 0};
static int digests(ENGINE *e, const EVP_MD **digest, const int **nids,
                   int nid) {
  if (!digest) {
    *nids = digest_nids;
    return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
  }
  switch (nid) {
  case NID_sha1:
    if (digest_meth == NULL) {
      digest_meth = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption);
      if (!digest_meth) {
        return 0;
      }
      if (!EVP_MD_meth_set_result_size(digest_meth, SHA_DIGEST_LENGTH) ||
          !EVP_MD_meth_set_flags(digest_meth, EVP_MD_FLAG_DIGALGID_ABSENT) ||
          !EVP_MD_meth_set_init(digest_meth, digest_init) ||
          !EVP_MD_meth_set_update(digest_meth, digest_update) ||
          !EVP_MD_meth_set_final(digest_meth, digest_final) ||
          !EVP_MD_meth_set_cleanup(digest_meth, NULL) ||
          !EVP_MD_meth_set_ctrl(digest_meth, NULL) ||
          !EVP_MD_meth_set_input_blocksize(digest_meth, SHA_CBLOCK) ||
          !EVP_MD_meth_set_app_datasize(
              digest_meth, sizeof(EVP_MD *) + sizeof(SHA256_CTX)) ||
          !EVP_MD_meth_set_copy(digest_meth, NULL)) {

        goto err;
      }
    }
    *digest = digest_meth;
    return 1;
  default:
    *digest = NULL;
    return 0;
  }

err:
  if (digest_meth) {
    EVP_MD_meth_free(digest_meth);
    digest_meth = NULL;
  }
  return 0;
}

static int engine_init(ENGINE *e) {
  return 1;
}

static int engine_finish(ENGINE *e) {
  if (digest_meth) {
    EVP_MD_meth_free(digest_meth);
    digest_meth = NULL;
  }
  return 1;
}

static int bind(ENGINE *e, const char *id) {
  if (!ENGINE_set_id(e, engine_id)) {
    goto err;
  }
  if (!ENGINE_set_name(e, engine_name)) {
    goto err;
  }
  if (!ENGINE_set_init_function(e, engine_init)) {
    goto err;
  }
  if (!ENGINE_set_finish_function(e, engine_finish)) {
    goto err;
  }
  if (!ENGINE_set_digests(e, digests)) {
    goto err;
  }
  return 1;
err:
  return 0;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

The engine above declares itself to OpenSSL as a SHA-1 implementation, but reuses the OpenSSL itself and calculates SHA-256 instead. It also truncates the output to 20 bytes not to confuse applications expecting a SHA-1 result. Let's test it:

```bash
$ gcc -shared -fPIC -o cryptofix_engine.so sha1-sha256.c
$ echo abc | openssl sha1
(stdin)= 03cfd743661f07975fa2f1220c5194cbaff48451
$ echo abc | openssl sha1 -engine ./cryptofix_engine.so
engine "sha1-sha256" set.
replacing SHA1 with SHA256
(stdin)= edeaaff3f1774ad2888673770c6d64097e391bc3
$ echo abc | sha256sum
edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb  -
```

Seems working as expected. Let's try it with our proprietary tool:

```bash
$ echo abc | LD_PRELOAD=./cryptofix_engine.so ./customhashv3
03cfd743661f07975fa2f1220c5194cbaff48451
```

Hmm... Nothing changed: we don't get our debug message and still have a SHA-1 as a result. The reason is: to make the engine available we also need to call [some OpenSSL API][openssl-engine-conf-api] to load and configure it! So not all OpenSSL based applications are engine aware. Obviously, the command line `openssl` utility we used above is: the engine config API is invoked when we specify the `-engine` parameter. There are others, like NGINX and OpenVPN - they have some directives in the configuration files, where the user can specify the desired OpenSSL engine. But most are not - developers just use OpenSSL as a crypto library and don't expect users to replace the crypto algorithms.

### Injecting code on process startup

As we established above our custom tool is not OpenSSL engine aware, so we somehow need to make it call the [OpenSSL engine configuration API][openssl-engine-conf-api] before it starts computing its first SHA-1. We could probably hook some other function, even from `libc`, and hope it will be used before the OpenSSL ones, but we would be subject to the above problem of a vendor update potentially breaking our hotfix.

A better way is to just implement the desired engine configuration in a function and mark it as an ["initialisation routine"][gcc-init]:

*autoload.c:*

```cpp
#define _GNU_SOURCE /* for dladdr and Dl_info */
#include <dlfcn.h>
#include <stdio.h>

#include <openssl/engine.h>

static void fatal(const char *msg) {
  fputs(msg, stderr);
  exit(1);
}

static __attribute__((constructor)) void engine_preload(void) {
  // OpenSSL dynamic engine needs a filesystem path to the engine
  // so we determine our own filesystem path first
  Dl_info dinfo;
  int res = dladdr((const void *)engine_preload, &dinfo);
  if (0 == res) {
    fatal("failed to query engine module info");
  }
  if (NULL == dinfo.dli_fname) {
    fatal("failed to determine engine filesystem path");
  }
  ENGINE_load_dynamic();
  ENGINE *e = ENGINE_by_id("dynamic");
  if (NULL == e) {
    fatal("failed to load OpenSSL dynamic engine");
  }

  res = ENGINE_ctrl_cmd_string(e, "SO_PATH", dinfo.dli_fname, 0);
  if (res <= 0) {
    fatal("failed to set SO_PATH parameter for dynamic engine");
  }
  res = ENGINE_ctrl_cmd_string(e, "ID", "sha1-sha256", 0);
  if (res <= 0) {
    fatal("failed to set ID parameter for dynamic engine");
  }
  res = ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);
  if (res <= 0) {
    fatal("failed to LOAD sha1-sha256 engine");
  }
  res = ENGINE_set_default(e, ENGINE_METHOD_ALL);
  if (res <= 0) {
    fatal("failed to set algorithms from sha1-sha256 engine as default");
  }
}
```

OpenSSL engine configuration API needs a filesystem path to the desired engine. We assume that the above code will be part of our `cryptofix_engine.so` library, so we just get the filesystem path for the currently executing module and pass it to the OpenSSL engine configuration API. But the magic here is in the function declaration: notice the `__attribute__((constructor))` in the prototype. It marks this code as an "initialisation routine", so it will be automatically executed on process startup even before the `main` function. And the beauty of this approach is that we don't rely on hooking any function in the target application. In fact, this code will always be executed regardless of the application logic as long as the application loads our shared library.

Let's recompile our `cryptofix_engine.so` including this function and test it:

```bash
$ gcc -shared -fPIC -o cryptofix_engine.so autoload.c sha1-sha256.c
$ echo abc | LD_PRELOAD=./cryptofix_engine.so ./customhashv3
replacing SHA1 with SHA256
edeaaff3f1774ad2888673770c6d64097e391bc3
$ echo abc | sha256sum
edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb  -
```

It worked! But because we replaced the algorithm via an OpenSSL engine it also works for every previous version of the tool and most likely for any future one:

```bash
$ echo abc | LD_PRELOAD=./cryptofix_engine.so ./customhashv2
replacing SHA1 with SHA256
edeaaff3f1774ad2888673770c6d64097e391bc3
$ echo abc | LD_PRELOAD=./cryptofix_engine.so ./customhash
replacing SHA1 with SHA256
edeaaff3f1774ad2888673770c6d64097e391bc3
```

So our hotfix is much more reliable now and future-proof.

### Getting rid of LD_PRELOAD

So far we have a reliable hotfix for our weak proprietary hasing tool, however we need to ensure our code will always be loaded by specifying the `LD_PRELOAD` environment variable, when the tool is being executed. This is not only error prone (we might just forget to define the variable, when invoking the tool), but also [does not work in all cases][ld-preload] (for example, the environment variable is ignored when invoking executables with [`setuid`/`setgid`][setuid] bit set).

We can permanently patch the custom tool without recompiling it and add our `cryptofix_engine.so` shared library as a runtime dependency:

```bash
$ patchelf --add-needed ./cryptofix_engine.so ./customhashv3
$ ldd ./customhashv3
	linux-vdso.so.1 (0x00007ffd40977000)
	./cryptofix_engine.so (0x00007faf1d1ce000)
	libcrypto.so.1.1 => /lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007faf1ced9000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007faf1cd18000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007faf1cd13000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007faf1ccf2000)
	/lib64/ld-linux-x86-64.so.2 (0x00007faf1d1db000)
```

From now on our `cryptofix_engine.so` will be part of the `customhashv3` tool and will always be loaded, when executing the binary even without any `LD_PRELOAD` definitions:

```bash
$ echo abc | ./customhashv3
replacing SHA1 with SHA256
edeaaff3f1774ad2888673770c6d64097e391bc3
$ echo abc | sha256sum
edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb  -
```

### Conclusions

This post, although based on imaginary scenario, reflects some of the real world use cases and experiences. It also covers some powerful runtime code patching approaches, which are useful even without the need to replace weak crypto in proprietary code and can be adopted separately or together. All code from the post is [published here][post-source-code].

[ec-drbg-backdoor]: https://en.wikipedia.org/wiki/Dual_EC_DRBG#Weakness:_a_potential_backdoor
[rc4nomore]: https://www.rc4nomore.com/
[quantum-computing]: https://en.wikipedia.org/wiki/Quantum_computing#Cryptography
[shattered-io]: https://shattered.io/
[openssl]: https://www.openssl.org/
[ld-preload]: http://man7.org/linux/man-pages/man8/ld.so.8.html
[libdl-man]: http://man7.org/linux/man-pages/man3/dlsym.3.html
[openssl-engine]: https://github.com/openssl/openssl/blob/master/README.ENGINE
[openssl-engine-example]: https://www.openssl.org/blog/blog/2015/11/23/engine-building-lesson-2-an-example-md5-engine/
[openssl-engine-conf-api]: https://www.openssl.org/docs/man1.1.1/man3/ENGINE_ctrl_cmd_string.html
[gcc-init]: https://gcc.gnu.org/onlinedocs/gccint/Initialization.html
[setuid]: https://en.wikipedia.org/wiki/Setuid
[post-source-code]: https://github.com/pqsec/cryptofix
