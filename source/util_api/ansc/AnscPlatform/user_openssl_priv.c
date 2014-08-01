/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#include "openssl/crypto.h"
#include "ansc_platform.h"
#include "openssl/ssl.h"

int openssl_priv_load_ca_certificates(int who_calls)
{
    return 0;
}


void openssl_priv_verify(SSL_CTX *ssl_ctx)
{
      /* see openssl_validate_certificate() for certificate validation  */
      /* if not using openssl_validate_certificate(), make sure to use SSL_VERIFY_PEER  */
      SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_NONE, NULL);
}

void openssl_priv_validate_hostname(char *common_name)
{
	return;
}
