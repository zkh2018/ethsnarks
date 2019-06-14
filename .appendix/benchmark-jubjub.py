"""
Example output:

a * x 0.13714
b * x 0.01573
c * x 0.01436
mult_naf(a, x) 0.12317
mult_naf(b, x) 0.01271
mult_naf(c, x) 0.01213
mult_naf_lut(a, x, 2) 0.12492
mult_naf_lut(b, x, 2) 0.013
mult_naf_lut(c, x, 2) 0.01291
mult_naf_lut(a, x, 3) 0.11661
mult_naf_lut(b, x, 3) 0.0121
mult_naf_lut(c, x, 3) 0.01146
mult_naf_lut(a, x, 4) 0.11175
mult_naf_lut(b, x, 4) 0.01177
mult_naf_lut(c, x, 4) 0.01107
mult_naf_lut(a, x, 5) 0.11282
mult_naf_lut(b, x, 5) 0.0116
mult_naf_lut(c, x, 5) 0.01066
mult_naf_lut(a, x, 6) 0.11055
mult_naf_lut(b, x, 6) 0.01152
mult_naf_lut(c, x, 6) 0.01094
mult_naf_lut(a, x, 7) 0.11351
mult_naf_lut(b, x, 7) 0.01203
mult_naf_lut(c, x, 7) 0.0114
mult_naf_lut(a, x, 8) 0.12455
mult_naf_lut(b, x, 8) 0.01385
mult_naf_lut(c, x, 8) 0.01263
mult_naf_lut(a, x, 9) 0.15009
mult_naf_lut(b, x, 9) 0.01616
mult_naf_lut(c, x, 9) 0.01561
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
for i in range(2, 10):
	for p in ['a', 'b', 'c']:
		bench('mult_naf_lut(%s, x, %d)' % (p, i))
