REBAR := ./rebar3
REBAR_URL := https://s3.amazonaws.com/rebar3/rebar3
ERL       ?= erl

.PHONY: all compile shell test clean xref dialyzer

all: compile

compile: $(REBAR)
	$(REBAR) compile

shell: $(REBAR)
	$(REBAR) shell

test: $(REBAR)
	$(REBAR) as test ct

clean: $(REBAR)
	$(REBAR) clean

xref: $(REBAR)
	$(REBAR) as test xref

dialyzer: $(REBAR)
	$(REBAR) as test dialyzer

./rebar3:
	$(ERL) -noshell -s inets -s ssl \
	  -eval '{ok, saved_to_file} = httpc:request(get, {"$(REBAR_URL)", []}, [], [{stream, "./rebar3"}])' \
	  -s init stop
	chmod +x ./rebar3
