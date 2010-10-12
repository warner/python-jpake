
import os, binascii
from hashlib import sha256, sha1
try:
    import json
except ImportError:
    import simplejson as json


class JPAKEError(Exception):
    pass

class DuplicateSignerID(JPAKEError):
    """Their signer ID must be different than ours, to keep them from merely
    echoing back our own signature."""

class BadZeroKnowledgeProof(JPAKEError):
    """They failed to prove knowledge of their own secret."""
class GX4MustNotBeOne(JPAKEError):
    pass


def orderlen(order):
    return (1+len("%x"%order))/2 # bytes

def number_to_string(num, orderlen):
    if orderlen is None:
        s = "%x" % num
        if len(s)%2:
            s = "0"+s
        string = binascii.unhexlify(s)
    else:
        fmt_str = "%0" + str(2*orderlen) + "x"
        string = binascii.unhexlify(fmt_str % num)
        assert len(string) == orderlen, (len(string), orderlen)
    return string

def string_to_number(string):
    return int(binascii.hexlify(string), 16)

class Params:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g
        self.orderlen = orderlen(self.p)

# params_80 is roughly as secure as an 80-bit symmetric key, and uses a
# 1024-bit modulus. params_112 uses a 2048-bit modulus, and params_128 uses a
# 3072-bit modulus.

params_80 = Params(p=0xfd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7,
                   q=0x9760508f15230bccb292b982a2eb840bf0581cf5,
                   g=0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a)

# 112, 128 from NIST
params_112 = Params(p=0xC196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83,
                    q=0x90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D,
                    g=0xA59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085)

params_128 = Params(p=0x90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA129F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504FB0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73,
                    q=0xCFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D,
                    g=0x5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B)


def randrange(order, entropy):
    """Return a random integer k such that 0 <= k < order, uniformly
    distributed across that range. For simplicity, this only behaves well if
    'order' is fairly close (but below) a power of 256. The try-try-again
    algorithm we use takes longer and longer time (on average) to complete as
    'order' falls, rising to a maximum of avg=512 loops for the worst-case
    (256**k)+1 . All of the standard curves behave well. There is a cutoff at
    10k loops (which raises RuntimeError) to prevent an infinite loop when
    something is really broken like the entropy function not working.

    Note that this function is not declared to be forwards-compatible: we may
    change the behavior in future releases. The entropy= argument (which
    should get a callable that behaves like os.entropy) can be used to
    achieve stability within a given release (for repeatable unit tests), but
    should not be used as a long-term-compatible key generation algorithm.
    """
    # we could handle arbitrary orders (even 256**k+1) better if we created
    # candidates bit-wise instead of byte-wise, which would reduce the
    # worst-case behavior to avg=2 loops, but that would be more complex. The
    # change would be to round the order up to a power of 256, subtract one
    # (to get 0xffff..), use that to get a byte-long mask for the top byte,
    # generate the len-1 entropy bytes, generate one extra byte and mask off
    # the top bits, then combine it with the rest. Requires jumping back and
    # forth between strings and integers a lot.

    assert order > 1
    bytes = orderlen(order)
    dont_try_forever = 10000 # gives about 2**-60 failures for worst case
    while dont_try_forever > 0:
        dont_try_forever -= 1
        candidate = string_to_number(entropy(bytes))
        if candidate < order:
            return candidate
        continue
    raise RuntimeError("randrange() tried hard but gave up, either something"
                       " is very wrong or you got realllly unlucky. Order was"
                       " %x" % order)

class JPAKE:
    """This class manages one half of a J-PAKE key negotiation.

    Create an instance with JPAKE(password), where 'password' is either a
    number (0 < number < params.q-1) or a bytestring. You can also pass an
    optional params= value (one of [params_80, params_112, params_128], for
    increasing levels of security and CPU usage), and a signerid= value
    (which must be an ASCII string). Any two JPAKE communicating instances
    must use different signerid= values (to prevent simply reflecting a
    message back to its sender): the default achieves this by using a random
    string, but you could use 'client' and 'server' if you only ever use this
    class in that way.

    Once constructed, you will need to call one(), two(), and three() in
    order, passing the output of one over the wire, where it forms the input
    to the next:

        my_msg1 = j.one()
        send(my_msg1)
        their_msg1 = receive()
        my_msg2 = j.two(their_msg1)
        send(my_msg2)
        their_msg2 = receive()
        key = j.three(their_msg2)

    The secret 'key' that comes out will be a bytestring (the output of a
    hash function). If both sides used the same password, both sides will
    wind up with the same key, otherwise they will have different keys. You
    will probably want to confirm this equivalence before relying upon it
    (but don't reveal the key to the other side in doing so, in case you
    aren't talking to the right party and your keys are really different).
    Note that this introduces an asymmetry to the protocol. For example:

        A: hhkey = sha256(sha256(Akey).digest()).digest()
        A: send(hhkey)
        B: hhkey = receive()
        B: assert sha256(sha256(Bkey).digest()).digest() == hhkey
        B: hkey = sha256(Bkey).digest()
        B: send(hkey)
        A: hkey = receive()
        A: assert sha256(Akey).digest() == hkey

    If you can't keep the JPAKE instance alive for the whole negotiation, you
    can persist the important data from an instance with data=j.to_json(),
    and then reconstruct the instance with j=JPAKE.from_json(data). The
    instance data is sensitive: protect it better than you would the original
    password. An attacker who learns the instance state from both sides will
    be able to reconstruct the shared key. These functions return a
    dictionary: you are responsible for invoking e.g. json.dumps() to
    serialize it into a string that can be written to disk. For params_80,
    the serialized JSON is typically about 750 bytes after construction, 1300
    bytes after one(), and 1800 bytes after two().

     j = JPAKE(password)
     send(j.one())
     open('save.json','w').write(json.dumps(j.to_json()))
     ...
     j = JPAKE.from_json(json.loads(open('save.json').read()))
     send(j.two(receive()))
     open('save.json','w').write(json.dumps(j.to_json()))
     ...
     j = JPAKE.from_json(json.loads(open('save.json').read()))
     key = j.three(receive())

    The messages returned by one() and two() are small dictionaries, safe to
    serialize as JSON objects, and will survive being deserialized in a
    javascript environment (i.e. the large numbers are encoded as hex
    strings, since JS does not have bigints). If you wish for smaller
    messages, the JPAKE instance has pack_msg1(), unpack_msg1(), pack_msg2(),
    unpack_msg2() methods to encode/decode these strings into smaller
    bytestrings. The encoding scheme is slightly different for each params=
    value. For params_80, a JSON encoding of one()/two() is 1218/606 bytes,
    while the output of pack_one()/pack_two() is 773/389 byes.

      send(j.pack_one(j.one()))
      msg2 = j.two(j.unpack_one(receive()))
      send(j.pack_two(msg2))
      key = j.three(j.unpack_two(receive()))

    """

    def __init__(self, password, params=params_80, signerid=None, entropy=None):
        if entropy is None:
            entropy = os.urandom
        self.entropy = entropy
        if signerid is None:
            signerid = binascii.hexlify(self.entropy(16))
        self.signerid = signerid
        assert json.dumps(self.signerid) # must be printable
        self.params = params
        q = params.q
        if isinstance(password, (int,long)):
            assert password > 0
            assert password < q-1
            self.s = password
        else:
            assert isinstance(password, str)
            # we must convert the password (a variable-length string) into a
            # number from 1 to q-1 (inclusive).
            self.s = 1 + (string_to_number(sha256(password).digest()) % (q-1))
        

    def createZKP(self, generator, exponent, gx):
        # This returns a proof that I know a secret value 'exponent' that
        # satisfies the equation A^exponent=B mod P, where A,B,P are known to
        # the recipient of this proof (A=generator, P=self.params.p). It
        # happens that everywhere createZKP() is called, we already have
        # A^exponent, so we pass it in to save some computation time.
        p = self.params.p; q = self.params.q
        r = randrange(q, self.entropy) # [0,q)
        gr = pow(generator, r, p)
        #gx = pow(generator, exponent, p) # the verifier knows this already
        # Ben's C implementation hashes the pieces this way:
        def hashbn(bn):
            bns = number_to_string(bn, None)
            assert len(bns) <= 0xffff
            return number_to_string(len(bns), 2) + bns
        assert len(self.signerid) <= 0xffff
        # we match the way OpenSSL does the hash:
        # http://git.infradead.org/openssl.git/blob/HEAD:/crypto/jpake/jpake.c#l342
        s = "".join([hashbn(generator), hashbn(gr), hashbn(gx),
                     number_to_string(len(self.signerid), 2),
                     self.signerid])
        h = string_to_number(sha1(s).digest())

        b = (r - exponent*h) % q
        return {"gr": "%x"%gr, # gr and b are the important values
                "b": "%x"%b,
                "id": self.signerid,
                }

    def checkZKP(self, generator, gx, zkp):
        # confirm the sender's proof (contained in 'zkp') that they know 'x'
        # such that generator^x==gx
        p = self.params.p
        gr = int(zkp["gr"], 16)
        b = int(zkp["b"], 16)
        if zkp["id"] == self.signerid:
            raise DuplicateSignerID
        # Ben's C implementation hashes the pieces this way:
        def hashbn(bn):
            bns = number_to_string(bn, None)
            assert len(bns) <= 0xffff
            return number_to_string(len(bns), 2) + bns
        assert len(zkp["id"]) <= 0xffff
        s = "".join([hashbn(generator), hashbn(gr), hashbn(gx),
                     number_to_string(len(zkp["id"]), 2),
                     str(zkp["id"])])
        h = string_to_number(sha1(s).digest())
        gb = pow(generator, b, p)
        y = pow(gx, h, p)
        if gr != (gb*y)%p:
            raise BadZeroKnowledgeProof

    def one(self):
        g = self.params.g; p = self.params.p; q = self.params.q
        self.x1 = randrange(q, self.entropy) # [0,q)
        self.x2 = 1+randrange(q-1, self.entropy) # [1,q)
        gx1 = self.gx1 = pow(g, self.x1, p)
        gx2 = self.gx2 = pow(g, self.x2, p)
        zkp_x1 = self.createZKP(g, self.x1, gx1)
        zkp_x2 = self.createZKP(g, self.x2, gx2)
        # now serialize all four. Use simple jsonable dict for now
        return {"gx1": "%x"%gx1,
                "gx2": "%x"%gx2,
                "zkp_x1": zkp_x1,
                "zkp_x2": zkp_x2,
                }

    def pack_one(self, data):
        orderlen = self.params.orderlen
        def n2s(hexint):
            return number_to_string(int(hexint,16), orderlen)
        assert data["zkp_x1"]["id"] == data["zkp_x2"]["id"]
        packed = "".join([n2s(data["gx1"]),
                          n2s(data["gx2"]),
                          n2s(data["zkp_x1"]["gr"]),
                          n2s(data["zkp_x1"]["b"]),
                          n2s(data["zkp_x2"]["gr"]),
                          n2s(data["zkp_x2"]["b"]),
                          # the rest of the string is signerid
                          data["zkp_x1"]["id"],
                          ])
        return packed

    def unpack_one(self, packed):
        orderlen = self.params.orderlen
        def generate_substrings(packed):
            for i in range(6):
                yield binascii.hexlify(packed[i*orderlen:(i+1)*orderlen])
            yield packed[6*orderlen:] # signerid
        g = generate_substrings(packed)
        data = { "gx1": g.next(),
                 "gx2": g.next(),
                 "zkp_x1": {"gr": g.next(), "b": g.next() },
                 "zkp_x2": {"gr": g.next(), "b": g.next() },
                 }
        signerid = g.next()
        assert isinstance(signerid, str)
        data["zkp_x1"]["id"] = signerid
        data["zkp_x2"]["id"] = signerid
        return data

    def two(self, m1):
        g = self.params.g; p = self.params.p
        gx3 = self.gx3 = int(m1["gx1"], 16) % p
        gx4 = self.gx4 = int(m1["gx2"], 16) % p
        if gx4 == 1:
            raise GX4MustNotBeOne
            
        self.checkZKP(g, gx3, m1["zkp_x1"])
        self.checkZKP(g, gx4, m1["zkp_x2"])
        # now compute A = g^((x1+x3+x4)*x2*s), i.e. (gx1*gx3*gx4)^(x2*s)
        t1 = (((self.gx1*gx3) % p) * gx4) % p   # (gx1*gx3*gx4)%p
        t2 = (self.x2*self.s) % p
        A = pow(t1, t2, p)
        # also create a ZKP for x2*s
        zkp_A = self.createZKP(t1, t2, A)
        return {"A": "%x"%A,
                "zkp_A": zkp_A,
                }

    def pack_two(self, data):
        orderlen = self.params.orderlen
        def n2s(hexint):
            return number_to_string(int(hexint,16), orderlen)
        packed = "".join([n2s(data["A"]),
                          n2s(data["zkp_A"]["gr"]),
                          n2s(data["zkp_A"]["b"]),
                          # the rest of the string is signerid
                          data["zkp_A"]["id"],
                          ])
        return packed

    def unpack_two(self, packed):
        orderlen = self.params.orderlen
        def generate_substrings(packed):
            for i in range(3):
                yield binascii.hexlify(packed[i*orderlen:(i+1)*orderlen])
            yield packed[3*orderlen:] # signerid
        g = generate_substrings(packed)
        data = { "A": g.next(),
                 "zkp_A": {"gr": g.next(), "b": g.next() },
                 }
        signerid = g.next()
        assert isinstance(signerid, str)
        data["zkp_A"]["id"] = signerid
        return data

    def three(self, m2):
        p = self.params.p; q = self.params.q
        B = int(m2["A"], 16)
        generator = (((self.gx1*self.gx2)%p)*self.gx3) % p
        self.checkZKP(generator, B, m2["zkp_A"])
        # we want (B/(g^(x2*x4*s)))^x2, using the g^x4 that we got from them
        # (stored in gx4). We start with gx4^x2, then (gx4^x2)^-s, then
        # (B*(gx4^x2)^-s), then finally apply the ^x2.
        t3 = pow(self.gx4, self.x2, p)
        t3 = pow(t3, q-self.s, p)
        t4 = (B * t3) % p
        K = pow(t4, self.x2, p)
        # the paper suggests this can be reduced to two pow() calls, but I'm
        # not seeing it.
        self.K = K # stash it, so that folks trying to be compatible with
                   # some OpenSSL-based implementation (which returns the raw
                   # K from JPAKE_get_shared_key()) can use alternative
                   # hashing schemes to get from K to the final key. It's
                   # important to hash K before using it, to not expose the
                   # actual number to anybody.
        key = sha256(number_to_string(K, self.params.orderlen)).digest()
        return key

    def getattr_hex(self, name):
        if hasattr(self, name):
            return "%x" % getattr(self, name)
        return None

    def to_json(self):
        return {"signerid": self.signerid,
                "params.p": "%x" % self.params.p,
                "params.g": "%x" % self.params.g,
                "params.q": "%x" % self.params.q,
                "s": self.s,
                "x1": self.getattr_hex("x1"),
                "x2": self.getattr_hex("x2"),
                "gx1": self.getattr_hex("gx1"),
                "gx2": self.getattr_hex("gx2"),
                "gx3": self.getattr_hex("gx3"),
                "gx4": self.getattr_hex("gx4"),
                }

    @classmethod
    def from_json(klass, data, entropy=None):
        p = Params(int(data["params.p"], 16),
                   int(data["params.q"], 16),
                   int(data["params.g"], 16))
        self = klass(data["s"], params=p, signerid=data["signerid"],
                     entropy=entropy)
        for name in ["x1", "x2", "gx1", "gx2", "gx3", "gx4"]:
            if data[name]:
                setattr(self, name, int(data[name], 16))
        return self
