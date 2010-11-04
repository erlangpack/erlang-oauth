
.PHONY: test

all: compile

compile:
	./rebar compile

clean: 
	./rebar clean

test:
	./rebar eunit

