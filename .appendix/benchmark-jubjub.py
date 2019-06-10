"""
Example output:

a * x 0.13946
b * x 0.01434
c * x 0.01446
mult_naf(a, x) 0.12216
mult_naf(b, x) 0.01379
mult_naf(c, x) 0.01266
mult_naf_lut(a, x, 2) 0.12619
mult_naf_lut(b, x, 2) 0.01323
mult_naf_lut(c, x, 2) 0.01435
mult_naf_lut(a, x, 3) 0.11867
mult_naf_lut(b, x, 3) 0.01255
mult_naf_lut(c, x, 3) 0.01143
mult_naf_lut(a, x, 4) 0.12152
mult_naf_lut(b, x, 4) 0.01244
mult_naf_lut(c, x, 4) 0.0122
mult_naf_lut(a, x, 5) 0.1344
mult_naf_lut(b, x, 5) 0.01411
mult_naf_lut(c, x, 5) 0.01319
mult_naf_lut(a, x, 6) 0.17117
mult_naf_lut(b, x, 6) 0.01765
mult_naf_lut(c, x, 6) 0.01757
mult_naf_lut(a, x, 7) 0.27296
mult_naf_lut(b, x, 7) 0.02904
mult_naf_lut(c, x, 7) 0.02754
"""

def bench(s):
	import timeit
	setup_code = 'from ethsnarks.jubjub import Point, mult_naf, mult_naf_lut, FQ; a = Point.random(); b = a.as_etec(); c = a.as_proj(); x = FQ.random()'
	n = 20
	r = timeit.timeit(s, setup_code, number=n)
	print(s, round(r / n, 5))

bench('a * x')
bench('b * x')
bench('c * x')
bench('mult_naf(a, x)')
bench('mult_naf(b, x)')
bench('mult_naf(c, x)')
for i in range(2,8):
	for p in ['a', 'b', 'c']:
		bench('mult_naf_lut(%s, x, %d)' % (p, i))
