MAKEFLAGS := -rR
winpe: winpe.c Makefile
ifneq "$(CC)" "gcc"
	clang -fsanitize=undefined -fsanitize-minimal-runtime -D_FORTIFY_SOURCE=2 -g3 \
	-Wl,-z,relro,-z,now -fPIC -owinpe -O2 -Weverything -Werror -Wno-c++98-compat \
	-Wno-gnu-zero-variadic-macro-arguments -Wno-disabled-macro-expansion -Wno-cast-align \
	-Wno-declaration-after-statement -Wno-unsafe-buffer-usage \
	-Wno-language-extension-token \
	-Wformat=2 \
	-D_GNU_SOURCE=1 -- winpe.c
else
	gcc -D_FORTIFY_SOURCE=2 -fcf-protection=full -mstack-protector-guard=tls \
	-fstack-check=specific -Wformat=2 \
	-Wl,-z,relro,-z,now -fPIC -owinpe -O2 -Wall -Wextra -Werror \
	winpe.c
endif
clean:
	rm -f winpe winpe.o
