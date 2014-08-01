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

    module:	web_vho_lsm.c

        For Web Server/Client/Application Implementation (WEB),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 1997 ~ 2002
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This module implements the advanced interface functions
        of the Web Virtual Host Object.

        *   WebVhoLsmNewContact
        *   WebVhoLsmClassifyClient
        *   WebVhoLsmExpireSession
        *   WebVhoLsmEndSession

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        03/18/02    initial revision.

**********************************************************************/


#include "web_vho_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        WebVhoLsmNewContact
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hSession
            );

    description:

        This function is called to when a client is connected without
        valid identifier information.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hSession
                Specifies the new session object created for this
                contact.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
WebVhoLsmNewContact
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSession
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PWEB_VIRTUAL_HOST_OBJECT        pMyObject    = (PWEB_VIRTUAL_HOST_OBJECT   )hThisObject;
    PWEB_VIRTUAL_HOST_PROPERTY      pProperty    = (PWEB_VIRTUAL_HOST_PROPERTY )&pMyObject->Property;
    PHTTP_HFP_INTERFACE             pHfpIf       = (PHTTP_HFP_INTERFACE        )pMyObject->hHfpIf;
    PWEB_LSM_INTERFACE              pLsmIf       = (PWEB_LSM_INTERFACE         )pMyObject->hLsmIf;
    PWEB_GENERAL_SESSION_OBJECT     pSession     = (PWEB_GENERAL_SESSION_OBJECT)hSession;

    returnStatus =
        pSession->SetLsmIdentifier
            (
                (ANSC_HANDLE)pSession,
                WEB_DEF_LSM_CLIENT_ID
            );

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        WebVhoLsmClassifyClient
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hSession
            );

    description:

        This function is called to when a client is connected with
        valid identifier information but no corresponding session.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hSession
                Specifies the new session object created for this
                contact.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
WebVhoLsmClassifyClient
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSession
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PWEB_VIRTUAL_HOST_OBJECT        pMyObject    = (PWEB_VIRTUAL_HOST_OBJECT   )hThisObject;
    PWEB_VIRTUAL_HOST_PROPERTY      pProperty    = (PWEB_VIRTUAL_HOST_PROPERTY )&pMyObject->Property;
    PHTTP_HFP_INTERFACE             pHfpIf       = (PHTTP_HFP_INTERFACE        )pMyObject->hHfpIf;
    PWEB_LSM_INTERFACE              pLsmIf       = (PWEB_LSM_INTERFACE         )pMyObject->hLsmIf;
    PWEB_GENERAL_SESSION_OBJECT     pSession     = (PWEB_GENERAL_SESSION_OBJECT)hSession;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        WebVhoLsmExpireSession
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hSession
            );

    description:

        This function is called to when a session object expires.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hSession
                Specifies the session object to be expired.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
WebVhoLsmExpireSession
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSession
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PWEB_VIRTUAL_HOST_OBJECT        pMyObject    = (PWEB_VIRTUAL_HOST_OBJECT   )hThisObject;
    PWEB_VIRTUAL_HOST_PROPERTY      pProperty    = (PWEB_VIRTUAL_HOST_PROPERTY )&pMyObject->Property;
    PHTTP_HFP_INTERFACE             pHfpIf       = (PHTTP_HFP_INTERFACE        )pMyObject->hHfpIf;
    PWEB_LSM_INTERFACE              pLsmIf       = (PWEB_LSM_INTERFACE         )pMyObject->hLsmIf;
    PWEB_GENERAL_SESSION_OBJECT     pSession     = (PWEB_GENERAL_SESSION_OBJECT)hSession;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        WebVhoLsmEndSession
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hSession
            );

    description:

        This function is called to when a session object ends.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hSession
                Specifies the session object to be ended.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
WebVhoLsmEndSession
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSession
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PWEB_VIRTUAL_HOST_OBJECT        pMyObject    = (PWEB_VIRTUAL_HOST_OBJECT   )hThisObject;
    PWEB_VIRTUAL_HOST_PROPERTY      pProperty    = (PWEB_VIRTUAL_HOST_PROPERTY )&pMyObject->Property;
    PHTTP_HFP_INTERFACE             pHfpIf       = (PHTTP_HFP_INTERFACE        )pMyObject->hHfpIf;
    PWEB_LSM_INTERFACE              pLsmIf       = (PWEB_LSM_INTERFACE         )pMyObject->hLsmIf;
    PWEB_GENERAL_SESSION_OBJECT     pSession     = (PWEB_GENERAL_SESSION_OBJECT)hSession;

    return  returnStatus;
}