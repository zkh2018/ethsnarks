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
