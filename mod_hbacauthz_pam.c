#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_auth.h"

static authz_status hbacauthz_handler(request_rec * r, const char * require_args, const void * parsed_require_args) {
	return AUTHZ_GRANTED;
}

static const authz_provider hbacauthz_pam_provider = {
        &hbacauthz_handler,
        NULL,
};

static void register_hooks(apr_pool_t *pool){
	ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP, "pam-account", AUTHZ_PROVIDER_VERSION, &hbacauthz_pam_provider, AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA hbacauthz_pam_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	register_hooks
};
