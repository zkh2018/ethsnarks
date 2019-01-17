from ethsnarks.eddsa import MiMCEdDSA

k, A = MiMCEdDSA.random_keypair()
A, sig, m = MiMCEdDSA.sign([1,2,3], k)
print(A, sig.R, sig.s, ' '.join(str(_) for _ in m))
