#include <security/pam_appl.h>
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "mod_auth.h"
#include "apr_strings.h"

#include <stdio.h>

static authz_status pam_hbac_authorize(request_rec * r, const char * pam_service, const char * login) {
	struct pam_conv pam_conversation = { NULL, NULL };
	pam_handle_t * pamh = NULL;
	int ret;
	ret = pam_start(pam_service, login, &pam_conversation, &pamh);
	if (ret == PAM_SUCCESS) {
		const char * remote_host_or_ip = ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, NULL);
		if (remote_host_or_ip) {
			ret = pam_set_item(pamh, PAM_RHOST, remote_host_or_ip);
		}
	}
	if (ret == PAM_SUCCESS) {
		char *uri = apr_psprintf(r->pool, "URI=%s", r->uri);
		ret = pam_putenv(pamh, uri);
	}
	if (ret == PAM_SUCCESS) {
		ret = pam_acct_mgmt(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
	}
	if (ret != PAM_SUCCESS) {
		const char * strerr = pam_strerror(pamh, ret);
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_hbacauthz_pam user %s: PAM error: %s", login, strerr);
		pam_end(pamh, ret);
		return AUTHZ_DENIED;
	}
	pam_end(pamh, ret);
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_hbacauthz_pam PAM authentication successful for user %s", login);
	return AUTHZ_GRANTED;
}

static authz_status hbacauthz_handler(request_rec * r, const char * require_args, const void * parsed_require_args) {
	if (!r->user) {
		return AUTHZ_DENIED_NO_USER;
	}

	const char * pam_service = ap_getword_conf(r->pool, &require_args);
	if (pam_service && pam_service[0]) {
		return pam_hbac_authorize(r, pam_service, r->user);
	}
	return AUTHZ_DENIED;
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
