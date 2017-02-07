ifeq ($(OS),Windows_NT)
	CLEAN = del /Q /F ebin\*.beam >NUL 2>&1
	MKEBIN = IF NOT EXIST "ebin\" (mkdir ebin)
else
	CLEAN = rm -rf ebin/*.beam
	MKEBIN = test -d ebin || mkdir ebin
endif

all: clean compile

clean:
	@$(CLEAN)

compile:
	@$(MKEBIN)
	@erl -make

test: clean compile
	@escript test.escript
