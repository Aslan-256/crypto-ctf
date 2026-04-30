from pwn import *
import json
from math import log

VALUES = ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six',
          'Seven', 'Eight', 'Nine', 'Ten', 'Jack', 'Queen', 'King']
SUITS = ['Clubs', 'Hearts', 'Diamonds', 'Spades']

def conn():
    if args.REMOTE:
        return remote('socket.cryptohack.org', 13383)
    else:
        return remote('localhost', 13383)
    
class RNG:
    mod = 2**61 - 1  # 9th mersenne prime

    def __init__(self, seed, mul, inc):
        self.state = seed
        self.mul = mul
        self.inc = inc

    def next(self):
        self.state = (self.state * self.mul + self.inc) % self.mod
        print(f"RNG state: {self.state}")
        return self.state
    
class Card:
    def __init__(self, value, suit):
        self.value = value
        self.suit = suit

    def __str__(self):
        return f"{self.value} of {self.suit}"

    def __eq__(self, other):
        return self.value == other.value

    def __gt__(self, other):
        return VALUES.index(self.value) > VALUES.index(other.value)
    
class Game:
    def __init__(self, seed, mul, inc):
        self.rng = RNG(seed, mul, inc)
        self.deck = [Card(value, suit) for suit in SUITS for value in VALUES]
        self.num_deals = self.shuffle()

    def rebase(self, n, b=52):
        if n < b:
            return [n]
        else:
            return [n % b] + self.rebase(n//b, b)

    def shuffle(self):
        self.deals = self.rebase(self.rng.next())
        print(f"deals: {self.deals}")
        return len(self.deals)

    def deal_card(self):
        index = self.deals.pop()
        if self.deals == []:
            self.num_deals = self.shuffle()

        return self.deck[index]
    
def recontruct_number_from_deals(deals):
    n = 0
    for i in range(len(deals)-1, -1, -1):
        n = n*52 + deals[i]
    return n

def get_index_of_card(deck, card):
    for i in range(len(deck)):
        if str(deck[i]) == card:
            return i
    return -1

def make_clever_choice(card_value):
    if card_value in ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six']:
        return "h"
    else:
        return "l"
    
def make_sure_choice(card_value, next_card_value):
    if VALUES.index(next_card_value) > VALUES.index(card_value):
        return "h"
    else:
        return "l"
    
deck = [Card(value, suit) for suit in SUITS for value in VALUES]

# ======================================================
# tests
# ======================================================
v = [1]+[2]
print(v)
print(v.pop())
print(v)
# ------------------------------------------------------
mod = 2**61 - 1 
print(log(mod, 52)) # expected: about 11, passed
# ------------------------------------------------------
test_deals = [12, 19] # expected = 1000
print(recontruct_number_from_deals(test_deals)) # passed
# ======================================================

# =========================================================
# idea and tests
# =========================================================
# we can wait for the first 11*3=33 deals, then reconstruct
# the internal 3 states of the RNG to recover the internal
# parameters and predict the next states for ever
# ---------------------------------------------------------
# Step 1: get the first 33 deals and reconstruct the 3
# internal states of the RNG 
r = conn()
prng_states = []
for j in range(3):
    card_idxs = []
    for i in range(11): 
        res = json.loads(r.recvline())
        round = res['round']
        dollars = res['$']
        hand = res['hand']
        msg = res['msg']
        card_idxs.append(get_index_of_card(deck, hand))
        # print(msg)
        card_value = hand.split(" of ")[0]
        # print(card_value)
        choice = json.dumps({"choice": make_clever_choice(card_value)})
        r.sendline(choice.encode())
    card_idxs.reverse()
    print(card_idxs)
    random_number = recontruct_number_from_deals(card_idxs)
    prng_states.append(random_number)
    print(random_number)
# ---------------------------------------------------------
# Step 2: reconstruct the internal parameters of the RNG
# s_1 = (m * s_0 + c) mod n
# s_2 = (m * s_1 + c) mod n
n = 2**61 - 1
s_0, s_1, s_2 = prng_states
m = (s_2 - s_1) * pow(s_1 - s_0, -1, n) % n
c = (s_1 - m * s_0) % n
print(f"n: {n}")
print(f"m: {m}")
print(f"c: {c}")
# ----------------------------------------------------------
# Step 3: predict all the next states and deals
# ----------------------------------------------------------
game = Game(s_2, m, c)
next_card_value = game.deal_card().value
TARGET_ROUNDS = 200
for i in range(TARGET_ROUNDS-11*3):
    print(f"Round {i+1}")
    res = json.loads(r.recvline())
    round = res['round']
    dollars = res['$']
    hand = res['hand']
    msg = res['msg']
    # print(msg)
    card_value = hand.split(" of ")[0]
    # print("Your current card: ", card_value)
    next_card_value = game.deal_card().value
    # print(f"Prediction hidden card: {next_card_value}")
    choice = json.dumps({"choice": make_sure_choice(card_value, next_card_value)})
    r.sendline(choice.encode())
    # print(r.recvline())
flag_line = r.clean(timeout=1)
flag = flag_line.decode().strip().split("crypto{")[1].split("}")[0]
print(f"crypto{{{flag}}}")

    
