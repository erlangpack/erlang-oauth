EFLAGS=-pa ebin -pa ../erlang-fmt/ebin -pa ../eunit/ebin -I../ -Iinclude

ERL := erl $(EFLAGS)

ERL_SOURCES := $(wildcard src/*.erl)

ERL_OBJECTS := $(ERL_SOURCES:src/%.erl=ebin/%.beam)


all: objects

objects: $(ERL_OBJECTS)

ebin/%.beam: src/%.erl
	@test -d ebin || mkdir ebin
	erlc $(EFLAGS) -W +debug_info -o ebin $<

clean:
	rm -rf ebin/*.beam erl_crash.dump

test: objects
	$(ERL) -noshell -s crypto -s oauth_unit test -s init stop

termie: objects
	$(ERL) -noshell -s crypto -s inets -s oauth_termie test -s init stop

shell: objects
	@$(ERL) -s crypto -s inets

dialyzer:
	dialyzer $(EFLAGS) --src -c src/
