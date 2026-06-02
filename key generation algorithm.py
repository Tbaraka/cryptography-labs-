import random
import math


def is_prime(n: int) -> bool:
    #Check primality using trial division
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, math.isqrt(n) + 1, 2):
        if n % i == 0:
            return False
    return True


def get_primes_in_range(low: int, high: int) -> list[int]:
    #Return all primes within [low, high]
    primes = []

    for n in range(low, high + 1):
        if is_prime(n):
            primes.append(n)

    return primes


def pick_two_distinct_primes(low: int, high: int) -> tuple[int, int]:
    #Randomly pick two distinct primes from the given range.
    primes = get_primes_in_range(low, high)

    if len(primes) < 2:
        raise ValueError("Not enough primes in range. Try a bigger range.")

    return random.sample(primes, 2)


if __name__ == "__main__":
    LOW = int(input("Enter lower bound: "))
    HIGH = int(input("Enter upper bound: "))

    print(f"\nSearching for primes in range [{LOW}, {HIGH}]...\n")

    p, q = pick_two_distinct_primes(LOW, HIGH)

    print("First prime (p):", p)
    print("Second prime (q):", q)

    print("\nVerification:")
    print("p is prime:", is_prime(p))
    print("q is prime:", is_prime(q))
    print("p and q are different:", p != q)