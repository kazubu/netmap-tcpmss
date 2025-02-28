PROG=	netmap_tcpmss
SRCS=	main.c
LDADD=	-lutil -lpthread
CFLAGS+=	-Ofast
.if defined(DEBUG)
CFLAGS+= -DDEBUG
.endif

.if defined(NO_VLAN)
CFLAGS+= -DNO_VLAN
.endif

MK_MAN=	no

.include <bsd.prog.mk>
