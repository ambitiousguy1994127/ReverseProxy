mod_iam_authn.la: mod_iam_authn.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_iam_authn.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_iam_authn.la
