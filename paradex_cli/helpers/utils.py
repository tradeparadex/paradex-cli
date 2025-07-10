import random

def get_random_max_fee(start=int(1e16), end=int(1e17)) -> int:
    return random.randint(start, end)
