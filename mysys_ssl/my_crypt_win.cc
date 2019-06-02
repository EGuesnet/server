/*
 Copyright (c) 2019, MariaDB Corporation.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1335  USA */

#include <my_global.h>
#include <string.h>
#include <my_crypt.h>
#include <bcrypt.h>

struct MY_CRYPT_CTX
{
  uchar  oiv[MY_AES_BLOCK_SIZE];
  uchar  iv[MY_AES_BLOCK_SIZE];
  uchar  buf[MY_AES_BLOCK_SIZE];
  BCRYPT_KEY_HANDLE key_handle;
  size_t buf_len;
  const  uchar* key;
  uint   key_len;
  ULONG  ivlen;
  bool   pad;
  bool   encrypt;
  bool   has_data;
  bool   use_iv;
  MY_ALIGNED(16) uchar key_obj[1];
};

static void fill_buf(MY_CRYPT_CTX* ctx, const uchar* src, uint len)
{
  DBUG_ASSERT(ctx->buf_len + len <= sizeof(ctx->buf));
  memcpy(ctx->buf + ctx->buf_len, src, len);
  ctx->buf_len += len;
}

static NTSTATUS crypt(MY_CRYPT_CTX *ctx, const uchar* in, ULONG inlen, uchar* out, bool pad, ULONG* bytes)
{
  ULONG out_len = my_aes_get_size(MY_AES_CBC, inlen);
  DBUG_ASSERT(!pad || ctx->pad);
  DWORD  flags = pad? BCRYPT_BLOCK_PADDING:0;
  uchar* iv = ctx->use_iv ? ctx->iv : 0;
  ULONG ivlen = ctx->use_iv ? ctx->ivlen : 0;
  NTSTATUS status;
  if (ctx->encrypt)
  {
    status = BCryptEncrypt(ctx->key_handle, (PUCHAR)in, inlen, 0,
      iv, ivlen, out, out_len, bytes, flags);
  }
  else
  {
    status = BCryptDecrypt(ctx->key_handle, (PUCHAR)in, inlen, 0,
      iv, ivlen, out, out_len, bytes, flags);
  }
  DBUG_ASSERT(!ctx->encrypt || BCRYPT_SUCCESS(status));
  return status;
}

/*
  Initializiation of AES algorithms (ECB and CBC)
  Needs to be done only once per program.
*/
struct AES_DATA
{
  BCRYPT_ALG_HANDLE ecb_handle;
  BCRYPT_ALG_HANDLE cbc_handle;
  DWORD key_buf_size;
  AES_DATA();
  ~AES_DATA();
};

inline AES_DATA::AES_DATA() :ecb_handle(0), cbc_handle(0), key_buf_size(0)
{
  NTSTATUS status;
  struct algo
  {
    BCRYPT_ALG_HANDLE* handle;
    const wchar_t* chaining_mode;
    ULONG chaining_mode_size;
  };

  algo algo_arr[] = {
     {&ecb_handle, BCRYPT_CHAIN_MODE_ECB, (ULONG)sizeof(BCRYPT_CHAIN_MODE_ECB)},
     {&cbc_handle, BCRYPT_CHAIN_MODE_CBC, (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC)},
     {0,0,0}
  };

  for (int i = 0; algo_arr[i].handle; i++)
  {
    algo* alg = &algo_arr[i];
    status = BCryptOpenAlgorithmProvider(alg->handle, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
      DBUG_ASSERT(0);
      return;
    }
    status = BCryptSetProperty(*(alg->handle), BCRYPT_CHAINING_MODE,
      (PBYTE)alg->chaining_mode, alg->chaining_mode_size, 0);
    if (!BCRYPT_SUCCESS(status))
    {
      DBUG_ASSERT(0);
      return;
    }
  }
  DWORD tmp;
  status = BCryptGetProperty(ecb_handle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&key_buf_size, sizeof(DWORD), &tmp, 0);
  if (!BCRYPT_SUCCESS(status))
  {
    DBUG_ASSERT(0);
    return;
  }
}

inline AES_DATA::~AES_DATA()
{
  if (ecb_handle)
    BCryptCloseAlgorithmProvider(ecb_handle, 0);
  if (cbc_handle)
    BCryptCloseAlgorithmProvider(cbc_handle, 0);
}

static AES_DATA aes_data;

extern "C" {
int my_aes_crypt_init(void* ctx_buf, enum my_aes_mode mode, int flags,
  const unsigned char* key, unsigned int klen,
  const unsigned char* iv, unsigned int ivlen)
{
  MY_CRYPT_CTX* ctx = (MY_CRYPT_CTX*)ctx_buf;
  HANDLE alg;
  switch (mode)
  {
  case MY_AES_ECB:
    alg = aes_data.ecb_handle;
    ctx->use_iv = false;
    break;
  case MY_AES_CBC:
    alg = aes_data.cbc_handle;
    ctx->use_iv = true;
    break;
  default:
    DBUG_ASSERT(0);
    return 1;
  }

  NTSTATUS status = BCryptGenerateSymmetricKey(alg, &ctx->key_handle,
    aes_data.key_buf_size?ctx->key_obj: NULL,
    aes_data.key_buf_size,
    (PBYTE)key,
    klen,
    0);

  if (!BCRYPT_SUCCESS(status))
  {
    DBUG_ASSERT(0);
    return 1;
  }

  DBUG_ASSERT(ivlen <= MY_AES_BLOCK_SIZE);
  ctx->ivlen = ivlen;
  if (ivlen > 0)
  {
    memcpy(ctx->oiv, iv, ivlen);
    memcpy(ctx->iv, iv, ivlen);
  }
  else
  {
    memset(ctx->oiv, 0, ivlen);
  }

  ctx->key = key;
  ctx->key_len = klen;

  compile_time_assert(ENCRYPTION_FLAG_DECRYPT == 0);
  compile_time_assert(ENCRYPTION_FLAG_ENCRYPT != 0);

  ctx->encrypt = (flags & ENCRYPTION_FLAG_ENCRYPT) != 0;
  ctx->pad = (flags & ENCRYPTION_FLAG_NOPAD) == 0;
  ctx->buf_len = 0;
  ctx->has_data = false;
  return 0;
}

int my_aes_crypt_update(void* ctx_buf, const uchar* src, uint slen, uchar* dst, uint* dlen)
{
  MY_CRYPT_CTX* ctx = (MY_CRYPT_CTX*)ctx_buf;
  DBUG_ASSERT(ctx->buf_len <= MY_AES_BLOCK_SIZE);

  ULONG out_len;
  NTSTATUS status;

  *dlen = 0;
  if (!slen)
  {
    return MY_AES_OK;
  }

  ctx->has_data = true;
  if (ctx->buf_len > 0)
  {
    if (ctx->buf_len + slen >= MY_AES_BLOCK_SIZE)
    {
      uint copy_len = (uint)(MY_AES_BLOCK_SIZE - ctx->buf_len);
      fill_buf(ctx,src,copy_len);
      src += copy_len;
      slen -= copy_len;

      if (slen == 0 && !ctx->encrypt && ctx->pad)
      {
        /* When decrypting with padding, save the full block, rather than decrypt,
          it might need a final check for padding.*/
        return MY_AES_OK;
      }

      ULONG out_len;
      status = crypt(ctx, ctx->buf, MY_AES_BLOCK_SIZE, dst, false, &out_len);
      if (!BCRYPT_SUCCESS(status))
      {
        return MY_AES_BAD_DATA;
      }
      (*dlen) += out_len;
      dst += out_len;
      ctx->buf_len = 0;
    }
    else
    {
      /* Small input length, just save to buffer. */
      fill_buf(ctx, src, slen);
      return MY_AES_OK;
    }
  }

  uint crypt_size = (slen / MY_AES_BLOCK_SIZE) * MY_AES_BLOCK_SIZE;

  if (slen == crypt_size && !ctx->encrypt && ctx->pad)
  {
    /* Do not decrypt last block yet, save it instead, might need final check for padding.*/
    crypt_size -= MY_AES_BLOCK_SIZE;
  }

  if (crypt_size)
  {
    status = crypt(ctx,src, crypt_size, dst, false, &out_len);
    if (!BCRYPT_SUCCESS(status))
    {
      return MY_AES_BAD_DATA;
    }
    (*dlen) += out_len;
  }

  if (crypt_size != slen)
  {
    fill_buf(ctx, src + crypt_size, slen - crypt_size);
  }
  return 0;
}

int my_aes_crypt_finish(void* ctx_buf, uchar* dst, uint* dlen)
{
  MY_CRYPT_CTX* ctx = (MY_CRYPT_CTX*)ctx_buf;
  *dlen = 0;
  int ret= MY_AES_OK;

  if (ctx->pad)
  {
    if (!ctx->encrypt && !ctx->has_data)
    {
      /* There should have been at least one block to decrypt, as it padding is set.*/
      ret = MY_AES_BAD_DATA;
      goto end;
    }
    compile_time_assert(sizeof(ULONG) == sizeof(uint));
    NTSTATUS status = crypt(ctx,ctx->buf, (ULONG)ctx->buf_len, dst, true, (ULONG*)dlen);
    if (!BCRYPT_SUCCESS(status))
    {
      ret= MY_AES_BAD_DATA;
      goto end;
    }
  }
  else if (ctx->buf_len)
  {
    uchar mask[MY_AES_BLOCK_SIZE];
    uint mlen;

    my_aes_crypt(MY_AES_ECB, ENCRYPTION_FLAG_ENCRYPT | ENCRYPTION_FLAG_NOPAD,
      ctx->oiv, sizeof(ctx->oiv), mask, &mlen, ctx->key, ctx->key_len, 0, 0);

    DBUG_ASSERT(mlen == sizeof(mask));
    for (size_t i = 0; i < ctx->buf_len; i++)
      dst[i] = ctx->buf[i] ^ mask[i];
    *dlen = (uint)ctx->buf_len;
  }

end:
  BCryptDestroyKey(ctx->key_handle);
  return ret;
}

int my_aes_crypt(enum my_aes_mode mode, int flags,
  const uchar* src, uint slen, uchar* dst, uint* dlen,
  const uchar* key, uint klen, const uchar* iv, uint ivlen)
{
  void *ctx=_malloca(my_aes_ctx_size(MY_AES_ECB));
  if (!ctx)
    return MY_AES_OPENSSL_ERROR;

  int res1, res2;
  uint d1 = 0, d2 = 0;
  if ((res1 = my_aes_crypt_init(ctx, mode, flags, key, klen, iv, ivlen)))
    return res1;
  res1 = my_aes_crypt_update(ctx, src, slen, dst, &d1);
  res2 = my_aes_crypt_finish(ctx, dst + d1, &d2);
  _freea(ctx);
  *dlen = d1 + d2;
  return res1 ? res1 : res2;
}

unsigned int my_aes_get_size(enum my_aes_mode, unsigned int source_length)
{
  return (source_length / MY_AES_BLOCK_SIZE + 1) * MY_AES_BLOCK_SIZE;
}


unsigned int my_aes_ctx_size(enum my_aes_mode)
{
  return  sizeof(MY_CRYPT_CTX) + aes_data.key_buf_size;
}

int my_random_bytes(uchar* buf, int num)
{
  NTSTATUS status = BCryptGenRandom(0, buf, num, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!BCRYPT_SUCCESS(status))
  {
    DBUG_ASSERT(0);
    return MY_AES_OPENSSL_ERROR;
  }
  return MY_AES_OK;
}
}
