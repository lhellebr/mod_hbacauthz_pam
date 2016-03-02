compile:
	rm mod_hbacauthz_pam.so || true
	apxs -c mod_hbacauthz_pam.c -lpam -Wall -pedantic && \
	mv .libs/mod_hbacauthz_pam.so . && \
	rm -rf .libs remove mod_hbacauthz_pam.la mod_hbacauthz_pam.lo mod_hbacauthz_pam.o mod_hbacauthz_pam.slo || \
	echo FAILED
