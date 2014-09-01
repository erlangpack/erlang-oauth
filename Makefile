DEPS_PLT=$(CURDIR)/.deps_plt
DEPS=erts kernel stdlib inets ssl crypto public_key

all: clean compile

clean:
	@rm -rf ebin/*.beam

compile:
	@test -d ebin || mkdir ebin
	@erl -make

test: clean compile
	@escript test.escript

$(DEPS_PLT):
	@echo Building local plt at $(DEPS_PLT)
	@echo
	@dialyzer --output_plt $(DEPS_PLT) --build_plt --apps $(DEPS)

dialyzer: compile $(DEPS_PLT)
	dialyzer --fullpath --plt $(DEPS_PLT) -Wrace_conditions -Wno_behaviours -r ./ebin -r 

typer:
	@typer ebin --plt $(DEPS_PLT) --annotate -r ./src
