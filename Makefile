all:
	cd loader && make $@
	cd postex && make $@
	cd mask && make $@

clean:
	cd loader && make $@
	cd postex && make $@
	cd mask && make $@
