setup.h: setup1.h find_m1_m2
	cat setup1.h > setup.h
	./find_m1_m2 >> setup.h

setup1.h: find_best_exps find_min_poly
	./find_best_exps > setup1.h
	./find_min_poly >> setup1.h

find_best_exps: find_best_exps.c bigint.c bigint.h
	gcc -o find_best_exps find_best_exps.c bigint.c -Wall -Wextra -std=c99 -O3

find_min_poly: find_min_poly.c
	gcc -o find_min_poly find_min_poly.c -Wall -Wextra -std=c99 -O3

find_m1_m2: setup1.h find_m1_m2.c
	gcc -o find_m1_m2 find_m1_m2.c -Wall -Wextra -std=c99 -O3

clean:
	rm -f setup1.h find_best_exps find_min_poly find_m1_m2
	rm -f setup.h

.PHONY: clean

