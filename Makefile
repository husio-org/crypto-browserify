# some options

MOCHA_REPORTER=list

# Directory and Source Path definitions

CMD_DIR =  ./node_modules/.bin

test: servertest

servertest:
	-$(CMD_DIR)/mocha -R $(MOCHA_REPORTER)

install:
	npm install

clean:

.PHONY: install test servertest  clean