SHELL=/bin/sh

EFLAGS=-pa ebin -pa ../erlang-fmt/ebin

all: compile

compile: clean
	test -d ebin || mkdir ebin
	erl $(EFLAGS) -make

clean:
	rm -rf ebin erl_crash.dump

test: compile
	erl $(EFLAGS) -noshell -eval 'crypto:start(), oauth_test:all(), c:q().'

termie: compile
	erl $(EFLAGS) -noshell -eval 'crypto:start(), inets:start(), oauth_test:termie(), c:q().'

i: compile
	erl $(EFLAGS) -eval 'crypto:start(), inets:start().'