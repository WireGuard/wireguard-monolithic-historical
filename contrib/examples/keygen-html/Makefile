curve25519_generate.js: src/curve25519_generate.c src/glue.js
	emcc -O2 --memory-init-file 0 --closure 1 --post-js src/glue.js -s 'EXTRA_EXPORTED_RUNTIME_METHODS=["Pointer_stringify"]' -o $@ src/curve25519_generate.c
clean:
	rm -f curve25519_generate.js
all: curve25519_generate.js
.PHONY: clean all
