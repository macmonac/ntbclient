PROJECT=ntbclient

all:
	@echo "make clean - Get rid of scratch and byte files"

clean:
	find . -name '*.pyc' -delete
