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


/**********************************************************************

    module: user_base_custom_windowsnt.h

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2007
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file gives the custom ANSC wrapper base 
        definitions.

    ---------------------------------------------------------------

    environment:

        platform dependent

    ---------------------------------------------------------------

    author:

        Ding Hua

**********************************************************************/

#ifndef  _ANSC_WRAPPER_BASE_CUSTOM_H_
#define  _ANSC_WRAPPER_BASE_CUSTOM_H_


/***************************************************************
        Platform/Compiler Specific Definitions
***************************************************************/
/*
 *  Indicate whether massive PRAGMA functions are supported
 */
#define  _ANSC_ENABLE_PRAGMA_

/*
 *  Endian order    -- note, if AL_IS_LITTLE_ENDIAN is still used
 *  in any platform, replace it with _ANSC_LITTLE_ENDIAN_!!!
 */
#define  _ANSC_LITTLE_ENDIAN_

/*
 *  Indicates whether word access has to occur on word boundary
 */
#define  _ANSC_BYTE_ACCESS_

/***************************************************************
                OS Specific Definitions
***************************************************************/

/***************************************************************
            Individual Module Conditional Definitions
***************************************************************/

/*
 *  Leave them here temporarily, should move to individual module
 *  custom definition header files.
 */

/*
 *  Indicates whether ANSC timer descriptoir object profiling is required
 */
/*#define  _ANSC_TDO_PROFILING_ */

/*
 * indicate whether to use mutex for spin lock on windowsnt: 
 */
#define  _ANSC_WIN32_USE_MUTEX_AS_SPINLOCK_ 

/*
 *  Indicates whether ANSC spinlock profiling is required
 */
/*#define  _ANSC_SPINLOCK_PROFILING_*/

/*#define  _ANSC_ENABLE_PROFILING_*/

/*#define  _ANSC_SOCKET_LIBRARY_*/
/*#define  _ANSC_SOCKET_TLS_LAYER_*/

/*#define  _ANSC_MULTICAST_ROUTING_*/

#define  _ANSC_LEAN_SNPU10_
#define  _ANSC_MEAN_SNPU10_

#define  _ANSC_ARP_CACHE_ARRAY_
#define  _ANSC_X509_CERT_

#define  _ANSC_FILE_SEARCH_
#define  _ANSC_FILE_GZIP_
/*#define  _ANSC_FILE_ZLIB_*/

/*#define  _ANSC_SLAP_LPC_*/

/*#define  _ANSC_DIRTY_PDO_*/
/*#define  _ANSC_TRACE_F_*/

/*#define  _ANSC_IP4S_IGMPV2_*/
#define  _ANSC_IP4S_IGMPV3_
#define  _ANSC_IGMP_PROXY_
#define  _ANSC_IGMP_SNOOPING_

/*#define  _ANSC_MIB2_PRINT_MIB_REG_*/

/*#define  _ANSC_GNPS_GRE_*/
/*#define  _ANSC_GNPS_PPTP_PAC_*/
/*#define  _ANSC_GNPS_L2TP_LAC_*/
#define  _ANSC_GNPS_PPPOE_
#define  _ANSC_GNPS_PPP_
#define  _ANSC_GNPS_SNPU3_
/*#define  _ANSC_GNPS_SNPU4_*/
/*#define  _ANSC_GNPS_TRUNKING_*/

/*#define _ANSC_IP4S_TCP_*/
#define _ANSC_IP4S_UDP_
/*#define _ANSC_IP4S_GTP_*/

#endif

