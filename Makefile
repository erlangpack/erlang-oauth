SOURCE_FILES := $(wildcard src/*.erl)


all: ebin

ebin: ebin/oauth.app $(SOURCE_FILES:src/%.erl=ebin/%.beam)

ebin/oauth.app: src/oauth.app
	@test -d ebin || mkdir ebin
	cp src/oauth.app ebin/oauth.app

ebin/%.beam: src/%.erl
	@test -d ebin || mkdir ebin
	erlc -W +debug_info -o ebin $<

clean:
	@rm -rf ebin erl_crash.dump
