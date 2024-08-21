PROG=	netmap_tcpmss
SRCS=	main.c
LDADD=	-lutil
CFLAGS=	-Ofast

MK_MAN=	no

.include <bsd.prog.mk>
