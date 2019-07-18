/*
 * Copyright (c) 2015-2018 Nexenta Systems, inc.
 *
 * This file is part of EdgeFS Project
 * (see https://github.com/Nexenta/edgefs).
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef FASTLZ_FASTLZLIB_H
#define FASTLZ_FASTLZLIB_H

/* extracted from fastlz.h */
#define FASTLZ_VERSION_STRING "0.1.0"

/* optional conf.h file if build with -DFASTLZ_INCLUDE_CONF_H */
#ifdef FASTLZ_INCLUDE_CONF_H
#include "conf.h"
#endif
#ifndef ZFASTEXTERN
#ifdef _WIN32
#ifdef FASTLZ_DLL
#define ZFASTEXTERN __declspec(dllexport)
#else
#define ZFASTEXTERN __declspec(dllimport)
#endif
#else
#define ZFASTEXTERN extern
#endif
#endif
#ifndef ZFASTINLINE
#define ZFASTINLINE
#endif

/* we are using only zlib types and defines, including z_stream_s */
#define NO_DUMMY_DECL
#include "zlib.h"

#if defined (__cplusplus)
extern "C" {
#endif

/* note: the 5% ratio (/20) is not sufficient - add 66 bytes too */
/* for LZ4, the expansion ratio is smaller, so we keep the biggest one */
#define EXPANSION_RATIO         10
#define EXPANSION_SECURITY      66
#define HEADER_SIZE             16

#define MIN_BLOCK_SIZE          64
#define DEFAULT_BLOCK_SIZE	262144
/* estimated upper boundary of compressed size */
#define BUFFER_BLOCK_SIZE (EXPANSION_SECURITY + \
  DEFAULT_BLOCK_SIZE + DEFAULT_BLOCK_SIZE / EXPANSION_RATIO + HEADER_SIZE*2)

/* opaque structure for "state" zlib structure member */
struct internal_state {
  /* magic ; must be BLOCK_MAGIC */
  char magic[8];

  /* compression level or decompression mode (ZFAST_LEVEL_*) */
  int level;

  /* buffered header and data read so far (if inHdrOffs != 0) */
  Bytef inHdr[HEADER_SIZE];
  uInt inHdrOffs;

  /* block size ; must be 2**(POWER_BASE+n) with n < 16 */
  uInt block_size;
  /* block type (BLOCK_TYPE_*) */
  uInt block_type;
  /* current block stream size (input data block except header) */
  uInt str_size;
  /* current output stream size (output data block) */
  uInt dec_size;

  /* buffered data offset in inBuff (iff inBuffOffs < str_size)*/
  uInt inBuffOffs;
  /* buffered data offset in outBuff (iff outBuffOffs < dec_size)*/
  uInt outBuffOffs;

  /* block compression backend function */
  int (*compress)(int level, const void* input, int length, void* output);

  /* block decompression backend function */
  int (*decompress)(const void* input, int length, void* output, int maxout); 

  /* buffered data input */
  Bytef inBuff[BUFFER_BLOCK_SIZE];
  /* buffered data output */
  Bytef outBuff[BUFFER_BLOCK_SIZE];
};

/* our typed internal state */
typedef struct internal_state zfast_stream_state;

/**
 * The zfast structure is identical to zlib one, except for the "state" opaque
 * member.
 * Do not use a stream initialized by fastlzlibDecompressInit() or
 * fastlzlibCompressInit() with zlib functions, or you will experience very
 * annoying crashes.
 **/
typedef z_stream zfast_stream;

/**
 * Backend compressor type.
 **/
typedef enum zfast_stream_compressor {
  COMPRESSOR_NUL,
  COMPRESSOR_LZ4,
  COMPRESSOR_LZ4HC,
  COMPRESSOR_SNAPPY,
  COMPRESSOR_FASTLZ,
  COMPRESSOR_END
} zfast_stream_compressor;

#define COMPRESSOR_DEFAULT	COMPRESSOR_LZ4

/*
 * Low boundary at which to fall back to COMPRESSOR_NUL
 */
#define COMPRESS_LOW_WATERMARK		128

/*
 * Extra space for NUL compression to hold up to 8MB stream
 */
#define COMPRESSOR_NUL_HEADLEN		4096

/**
 * Return the fastlz library version.
 * (zlib equivalent: zlibVersion)
 **/
ZFASTEXTERN const char * fastlzlibVersion(void);

/**
 * Initialize a compressing stream, and sets on-stack zstate struct.
 * Returns Z_OK upon success.
 **/
ZFASTEXTERN int fastlzlibCompressInit(zfast_stream *s,
    zfast_stream_state *zstate);

/**
 * Initialize a decompressing stream.
 * Returns Z_OK upon success, Z_MEM_ERROR upon memory allocation error.
 * (zlib equivalent: inflateInit)
 **/
ZFASTEXTERN int fastlzlibDecompressInit(zfast_stream *s,
    zfast_stream_state *zstate);

/**
 * Set the block compressor type.
 * Returns Z_OK upon success, Z_VERSION_ERROR upon if the compressor is not
 * supported.
 **/
ZFASTEXTERN int fastlzlibSetCompressor(zfast_stream *s,
                                       zfast_stream_compressor compressor);

/**
 * Set the block compressor function.
 * The corresponding decompressor should be set using fastlzlibSetDecompress()
 **/
ZFASTEXTERN void fastlzlibSetCompress(zfast_stream *s,
                                      int (*compress)(int level,
                                                      const void* input,
                                                      int length,
                                                      void* output));

/**
 * Set the block decompressor function.
 * The corresponding compressor should be set using fastlzlibSetCompress()
 **/
ZFASTEXTERN void fastlzlibSetDecompress(zfast_stream *s,
                                        int (*decompress)(const void* input,
                                                          int length,
                                                          void* output,
                                                          int maxout));

/**
 * Free allocated data.
 * Returns Z_OK upon success.
 * (zlib equivalent: deflateEnd)
 **/
ZFASTEXTERN int fastlzlibCompressEnd(zfast_stream *s);

/**
 * Free allocated data.
 * Returns Z_OK upon success.
 * (zlib equivalent: inflateEnd)
 **/
ZFASTEXTERN int fastlzlibDecompressEnd(zfast_stream *s);

/**
 * Free allocated data by a compressing or decompressing stream.
 * Returns Z_OK upon success.
 **/
#define fastlzlibEnd fastlzlibCompressEnd

/**
 * Reset.
 * Returns Z_OK upon success.
 * (zlib equivalent: deflateReset)
 **/
ZFASTEXTERN int fastlzlibCompressReset(zfast_stream *s);

/**
 * Reset.
 * Returns Z_OK upon success.
 * (zlib equivalent: inflateReset)
 **/
ZFASTEXTERN int fastlzlibDecompressReset(zfast_stream *s);

/**
 * Reset a compressing or decompressing stream.
 * Returns Z_OK upon success.
 **/
#define fastlzlibReset fastlzlibCompressReset

/**
 * Decompress.
 * (zlib equivalent: inflate)
 **/
ZFASTEXTERN int fastlzlibDecompress(zfast_stream *s);

/**
 * Compress.
 * (zlib equivalent: deflate)
 **/
ZFASTEXTERN int fastlzlibCompress(zfast_stream *s, int flush);

/**
 * Decompress.
 * @arg may_buffer if non zero, accept to process partially a stream by using
 * internal buffers. if zero, input data shortage or output buffer room shortage
 * will return Z_BUF_ERROR. in this case, the client should ensure that the
 * input data provided and the output buffer are large enough before calling
 * again the function. (the output buffer should be validated before getting
 * this code, to ensure that Z_BUF_ERROR implies a need to read
 * additional input data)
 * @arg flush if set to Z_SYNC_FLUSH, process until the next block is reached,
 * and, if reached, return Z_NEED_DICT (a code currently unused outside this
 * function). this flag can be used to synchronize an input compressed stream
 * to a block, and seek to a desired position without the need of decompressing
 * or reading the stream, by skipping each compressed block.
 * see also s->total_out to get the current stream position, and
 * fastlzlibGetStreamInfo() to get information on compressed blocks
 **/
ZFASTEXTERN int fastlzlibDecompress2(zfast_stream *s, int flush,
                                     const int may_buffer);

/**
 * Compress.
 * @arg may_buffer if non zero, accept to process partially a stream by using
 * internal buffers. if zero, input data shortage or output buffer room shortage
 * will return Z_BUF_ERROR. in this case, the client should ensure that the
 * input data provided and the output buffer are large enough before calling
 * again the function. (the output buffer should be validated before getting
 * this code, to ensure that Z_BUF_ERROR implies a need to read additional
 * input data)
 **/
ZFASTEXTERN int fastlzlibCompress2(zfast_stream *s, int flush,
                                   const int may_buffer);

/**
 * Skip invalid data until a valid marker is found in the stream. All skipped
 * data will be lost, and associated uncompressed data too.
 * Call this function after fastlzlibDecompress() returned Z_DATA_ERROR to
 * locate the next valid compressed block.
 * Returns Z_OK upon success.
 * (zlib equivalent: inflateSync)
 **/
ZFASTEXTERN int fastlzlibDecompressSync(zfast_stream *s);

/**
 * Return the header size, that is, the fixed size of data at the begining of
 * a stream which contains details on the compression type..
 **/
ZFASTEXTERN int fastlzlibGetHeaderSize(void);

/**
 * Return the block size, that is, a size hint which can be used as a lower
 * bound for output buffer allocation and input buffer reads.
 **/
ZFASTEXTERN int fastlzlibGetBlockSize(zfast_stream *s);

/**
 * Return the block size of a compressed stream begining with "input".
 * Returns 0 if the stream is invalid or too short.
 * You may use fastlzlibGetHeaderSize() to know how many bytes needs to be
 * read for identifying a stream.
 **/
ZFASTEXTERN int fastlzlibGetStreamBlockSize(const void* input, int length);

/**
 * Return the last error message, if any.
 * Returns NULL if no specific error message was stored.
 **/
ZFASTEXTERN const char* fastlzlibGetLastErrorMessage(zfast_stream *s);

/**
 * Return the block size of a compressed stream begining with "input".
 * Returns Z_OK if the two members were successfully filles, Z_DATA_ERROR if
 * the stream is not a valid start of block, Z_BUF_ERROR if the buffer is too
 * small, and Z_STREAM_ERROR if arguments are invalid (NULL pointer).
 * You may use fastlzlibGetHeaderSize() to know how many bytes needs to be
 * read for identifying a stream.
 **/
ZFASTEXTERN int fastlzlibGetStreamInfo(const void* input, int length,
                                       uInt *compressed_size,
                                       uInt *uncompressed_size);

/**
 * Check if the given data is a fastlz compressed stream.
 * Returns Z_OK is the stream is a fastlz compressed stream, Z_BUF_ERROR is the
 * input data size is too small, and Z_DATA_ERROR is the stream is not a
 * fastlz stream.
 **/
ZFASTEXTERN int fastlzlibIsCompressedStream(const void* input, int length);

/**
 * Return the internal memory buffers size.
 * Returns -1 upon error.
 **/
ZFASTEXTERN int fastlzlibCompressMemory(zfast_stream *s);

/**
 * Return the internal memory buffers size.
 * Returns -1 upon error.
 **/
ZFASTEXTERN int fastlzlibDecompressMemory(zfast_stream *s);

#if defined (__cplusplus)
}
#endif

#endif
