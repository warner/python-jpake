#! /usr/bin/python

import timeit, sys
from jpake import JPAKE, params_80, params_112, params_128

class Harness:
    def setup(self, params=params_80):
        self.params = params
        self.pw = pw = "password"
        self.jA = JPAKE(pw, signerid="Alice", params=params)
        self.jB = JPAKE(pw, signerid="Bob", params=params)
        self.m1A,self.m1B = self.jA.one(), self.jB.one()
        self.m2A,self.m2B = self.jA.two(self.m1B), self.jB.two(self.m1A)
        #kA,kB = self.jA.three(m2B), self.jB.three(m2A)
    def construct(self):
        JPAKE(self.pw, signerid="Alice", params=self.params)
    def one(self):
        self.jA.one()
    def two(self):
        self.jA.two(self.m1B)
    def three(self):
        self.jA.three(self.m2B)

h = Harness()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        all_params = ["params_80", "params_112", "params_128"]
        all_names = ["construct", "one", "two", "three"]
    else:
        params,name = sys.argv[1].split(".")
        all_params = [params]
        all_names = [name]
    for params in all_params:
        for name in all_names:
            print "%s %s:" % (params, name),
            timeit.main(["--setup",
                         ("import bench_jpake; "
                          "bench_jpake.h.setup(bench_jpake.%s)" % params),
                         "bench_jpake.h.%s()" % name,
                         ])
            

# 41:warner@Cookies% python bench_jpake.py 
# params_80 construct: 10000 loops, best of 3: 101 usec per loop
# params_80 one: 10 loops, best of 3: 57.1 msec per loop
# params_80 two: 10 loops, best of 3: 94 msec per loop
# params_80 three: 10 loops, best of 3: 48.1 msec per loop
# params_112 construct: 10000 loops, best of 3: 107 usec per loop
# params_112 one: 10 loops, best of 3: 275 msec per loop
# params_112 two: 10 loops, best of 3: 428 msec per loop
# params_112 three: 10 loops, best of 3: 219 msec per loop
# params_128 construct: 10000 loops, best of 3: 83 usec per loop
# params_128 one: 10 loops, best of 3: 635 msec per loop
# params_128 two: 10 loops, best of 3: 966 msec per loop
# params_128 three: 10 loops, best of 3: 492 msec per loop
