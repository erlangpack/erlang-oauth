REBAR=`which rebar || ./rebar`

.PHONY: deps

all: compile

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean
