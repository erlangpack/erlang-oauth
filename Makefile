SHELL=/bin/sh

EFLAGS=-pa ebin -pa ../erlang-fmt/ebin -pa ../eunit/ebin

all: compile

compile: clean
	test -d ebin || mkdir ebin
	erl $(EFLAGS) -make

clean:
	rm -rf ebin erl_crash.dump

test: compile
	erl $(EFLAGS) -noshell -s crypto -s oauth_unit test -s init stop

termie: compile
	erl $(EFLAGS) -noshell -s crypto -s inets -s oauth_termie test -s init stop

i: compile
	erl $(EFLAGS) -s crypto -s inets