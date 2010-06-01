
import unittest
from jpake import JPAKE, DuplicateSignerID, params_80, params_112, params_128
from binascii import hexlify
from hashlib import sha256
from pprint import pprint

class Basic(unittest.TestCase):
    def test_success(self):
        pw = "password"
        jA,jB = JPAKE(pw, signerid="Alice"), JPAKE(pw, signerid="Bob")
        m1A,m1B = jA.one(), jB.one()
        pprint(("m1A", m1A))
        pprint(("m1B", m1B))
        m2A,m2B = jA.two(m1B), jB.two(m1A)
        pprint(("m2A", m2A))
        pprint(("m2B", m2B))
        kA,kB = jA.three(m2B), jB.three(m2A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

    def test_failure(self):
        pw = "password"
        jA,jB = JPAKE(pw), JPAKE("passwerd")
        m1A,m1B = jA.one(), jB.one()
        m2A,m2B = jA.two(m1B), jB.two(m1A)
        kA,kB = jA.three(m2B), jB.three(m2A)
        self.failIfEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))
        self.failUnlessEqual(len(kB), len(sha256().digest()))

class Parameters(unittest.TestCase):
    def do_tests(self, params):
        pw = "password"
        jA,jB = JPAKE(pw, params=params), JPAKE(pw, params=params)
        m1A,m1B = jA.one(), jB.one()
        m2A,m2B = jA.two(m1B), jB.two(m1A)
        kA,kB = jA.three(m2B), jB.three(m2A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

        jA,jB = JPAKE(pw), JPAKE("passwerd")
        m1A,m1B = jA.one(), jB.one()
        m2A,m2B = jA.two(m1B), jB.two(m1A)
        kA,kB = jA.three(m2B), jB.three(m2A)
        self.failIfEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))
        self.failUnlessEqual(len(kB), len(sha256().digest()))

    def test_params(self):
        for params in [params_80, params_112, params_128]:
            self.do_tests(params)

class SignerID(unittest.TestCase):
    def test_signerid(self):
        pw = "password"
        jA,jB = JPAKE(pw, signerid="a"), JPAKE(pw, signerid="b")
        m1A,m1B = jA.one(), jB.one()
        m2A,m2B = jA.two(m1B), jB.two(m1A)
        kA,kB = jA.three(m2B), jB.three(m2A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

        jA,jB = JPAKE(pw, signerid="a"), JPAKE("passwerd", signerid="b")
        m1A,m1B = jA.one(), jB.one()
        m2A,m2B = jA.two(m1B), jB.two(m1A)
        kA,kB = jA.three(m2B), jB.three(m2A)
        self.failIfEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))
        self.failUnlessEqual(len(kB), len(sha256().digest()))

        jA,jB = JPAKE(pw, signerid="same"), JPAKE(pw, signerid="same")
        m1A,m1B = jA.one(), jB.one()
        self.failUnlessRaises(DuplicateSignerID, jA.two, m1B)
        self.failUnlessRaises(DuplicateSignerID, jB.two, m1A)


class PRNG:
    # this returns a callable which, when invoked with an integer N, will
    # return N pseudorandom bytes.
    def __init__(self, seed):
        self.generator = self.block_generator(seed)

    def __call__(self, numbytes):
        return "".join([self.generator.next() for i in range(numbytes)])

    def block_generator(self, seed):
        counter = 0
        while True:
            for byte in sha256("prng-%d-%s" % (counter, seed)).digest():
                yield byte
            counter += 1

class OtherEntropy(unittest.TestCase):
    def test_entropy(self):
        entropy = PRNG("seed")
        pw = "password"
        jA,jB = JPAKE(pw, entropy=entropy), JPAKE(pw, entropy=entropy)
        m1A1,m1B1 = jA.one(), jB.one()
        m2A1,m2B1 = jA.two(m1B1), jB.two(m1A1)
        kA1,kB1 = jA.three(m2B1), jB.three(m2A1)
        self.failUnlessEqual(hexlify(kA1), hexlify(kB1))

        # run it again with the same entropy stream: all messages should be
        # identical
        entropy = PRNG("seed")
        jA,jB = JPAKE(pw, entropy=entropy), JPAKE(pw, entropy=entropy)
        m1A2,m1B2 = jA.one(), jB.one()
        m2A2,m2B2 = jA.two(m1B2), jB.two(m1A2)
        kA2,kB2 = jA.three(m2B2), jB.three(m2A2)
        self.failUnlessEqual(hexlify(kA2), hexlify(kB2))

        self.failUnlessEqual(m1A1, m1A2)
        self.failUnlessEqual(m1B1, m1B2)
        self.failUnlessEqual(m2A1, m2A2)
        self.failUnlessEqual(m2B1, m2B2)
        self.failUnlessEqual(kA1, kA2)
        self.failUnlessEqual(kB1, kB2)

if __name__ == '__main__':
    unittest.main()

