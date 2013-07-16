# some options

MOCHA_REPORTER=list

test: servertest

servertest:
	-$(CMD_DIR)/mocha -R $(MOCHA_REPORTER)

install:
	npm install

clean:

.PHONY: install test servertest  clean