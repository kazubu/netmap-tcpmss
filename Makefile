PROG=	netmap_tcpmss
SRCS=	main.c
LDADD=	-lutil

MK_MAN=	no

.include <bsd.prog.mk>
