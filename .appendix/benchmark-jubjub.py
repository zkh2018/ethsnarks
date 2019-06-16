"""
Example output:

a = Affine twisted Edwards
b = Projective twisted Edwards
c = extended twisted Edwards
d = Affine Montgomery

a * x 0.13991
b * x 0.01393
c * x 0.01457
d * x 0.07344
mult_naf(a, x) 0.12074
mult_naf(b, x) 0.01289
mult_naf(c, x) 0.01215
mult_naf(d, x) 0.06434
mult_naf_lut(a, x, 2) 0.12352
mult_naf_lut(b, x, 2) 0.01331
mult_naf_lut(c, x, 2) 0.01247
mult_naf_lut(d, x, 2) 0.06731
mult_naf_lut(a, x, 3) 0.11875
mult_naf_lut(b, x, 3) 0.01259
mult_naf_lut(c, x, 3) 0.01117
mult_naf_lut(d, x, 3) 0.06319
mult_naf_lut(a, x, 4) 0.11229
mult_naf_lut(b, x, 4) 0.0118
mult_naf_lut(c, x, 4) 0.01122
mult_naf_lut(d, x, 4) 0.06054
mult_naf_lut(a, x, 5) 0.11454
mult_naf_lut(b, x, 5) 0.01138
mult_naf_lut(c, x, 5) 0.01098
mult_naf_lut(d, x, 5) 0.06135
mult_naf_lut(a, x, 6) 0.11214
mult_naf_lut(b, x, 6) 0.01138
mult_naf_lut(c, x, 6) 0.01166
mult_naf_lut(d, x, 6) 0.06127
mult_naf_lut(a, x, 7) 0.11996
mult_naf_lut(b, x, 7) 0.01189
mult_naf_lut(c, x, 7) 0.01192
mult_naf_lut(d, x, 7) 0.06264
mult_naf_lut(a, x, 8) 0.12416
mult_naf_lut(b, x, 8) 0.01317
mult_naf_lut(c, x, 8) 0.01285
mult_naf_lut(d, x, 8) 0.06889
mult_naf_lut(a, x, 9) 0.15301
mult_naf_lut(b, x, 9) 0.0176
mult_naf_lut(c, x, 9) 0.01642
mult_naf_lut(d, x, 9) 0.08172
"""

def bench(s):
	import timeit
	setup_code = 'from ethsnarks.jubjub import Point, mult_naf, mult_naf_lut, FQ; a = Point.random(); b = a.as_etec(); c = a.as_proj(); d = a.as_mont(); x = FQ.random()'
	n = 20
	r = timeit.timeit(s, setup_code, number=n)
	print(s, round(r / n, 5))


for p in ['a', 'b', 'c', 'd']:
	bench('%s * x' % (p,))


for p in ['a', 'b', 'c', 'd']:
	bench('mult_naf(%s, x)' % (p,))


for i in range(2, 10):
	for p in ['a', 'b', 'c', 'd']:
		bench('mult_naf_lut(%s, x, %d)' % (p, i))
