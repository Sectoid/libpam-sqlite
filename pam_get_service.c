/*
 * Copyright (c) 2000. Leon Breedt, Copyright (c) 2002 David D.W. Downey
 */

/* $Id: pam_get_service.c,v 1.1 2003/06/20 09:56:31 ek Exp $ */
#include <security/pam_modules.h>
#include <stddef.h>

const char *pam_get_service(pam_handle_t *pamh)
{
    const char *service = NULL;

	if(pam_get_item(pamh, PAM_SERVICE, (void *) &service) != PAM_SUCCESS)
        return NULL;
    return service;
}
