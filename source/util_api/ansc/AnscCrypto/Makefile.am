AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -D_NO_PKI_KB5_SUPPORT
AM_CFLAGS += -D_ANSC_USE_OPENSSL_
AM_CFLAGS += -D_ANSC_AES_USED_
AM_CFLAGS += -D_CCSP_CWMP_TCP_CONNREQ_HANDLER
AM_CFLAGS += -D_DSLH_STUN_
AM_CFLAGS += -D_BBHM_SSE_FILE_IO
AM_CFLAGS += -DENABLE_SA_KEY
AM_CFLAGS += -D_ANSC_IPV6_COMPATIBLE_
AM_CFLAGS += -DBUILD_WEB
AM_LDFLAGS = -lpthread
AM_LDFLAGS += -lrt
AM_LDFLAGS +=
AM_LDFLAGS +=
AM_LDFLAGS += -lz

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

noinst_LTLIBRARIES = libCcspCommonLibrary_AnscCrypto.la
libCcspCommonLibrary_AnscCrypto_la_CPPFLAGS = -I$(top_srcdir)/source/cosa/include/linux -I$(top_srcdir)/source/debug_api/include -I$(top_srcdir)/source/ccsp/components/common/PoamIrepFolder -I$(top_srcdir)/source/cosa/include -I$(top_srcdir)/source/cosa/utilities/include -I$(top_srcdir)/source/cosa/custom -I$(top_srcdir)/source/cosa/package/bmw2/bwsp/include -I$(top_srcdir)/source/cosa/package/bmw2/include -I$(top_srcdir)/source/cosa/package/bmw2/bree/include -I$(top_srcdir)/source/cosa/package/bmw2/beep/include -I$(top_srcdir)/source/cosa/package/bmw2/bwrm/include -I$(top_srcdir)/source/cosa/package/system/include -I$(top_srcdir)/source/cosa/package/slap/include -I$(top_srcdir)/source/cosa/package/slap/services/dslh/include -I$(top_srcdir)/source/cosa/package/slap/services/bmc2/include -I$(top_srcdir)/source/cosa/package/cli/include -I$(top_srcdir)/source/cosa/package/bmc2/include -I$(top_srcdir)/source/debug_api/include -I$(top_srcdir)/source/ccsp/include -I$(top_srcdir)/source/ccsp/components/include -I$(top_srcdir)/source/ccsp/components/common/MessageBusHelper/include -I$(top_srcdir)/source/ccsp/custom -I$(top_srcdir)/source/util_api/tls/include -I$(top_srcdir)/source/util_api/web/include -I$(top_srcdir)/source/util_api/ansc/include -I$(top_srcdir)/source/util_api/stun/include -I$(top_srcdir)/source/util_api/http/include -I$(top_srcdir)/source/util_api/http/utilities/include -I$(top_srcdir)/source/util_api/asn.1/include $(CPPFLAGS)
libCcspCommonLibrary_AnscCrypto_la_SOURCES = ansc_crypto_utility.c ansc_crypto_interface.c ansc_crypto_random.c ansc_crypto_decompression.c ansc_crypto_base.c ansc_crypto_decryption.c ansc_crypto_encryption.c ansc_crypto_compression.c ansc_crypto_key.c ansc_crypto_digestion.c ansc_crypto_hash.c
libCcspCommonLibrary_AnscCrypto_la_LDFLAGS =  -lpthread -lrt -lz
