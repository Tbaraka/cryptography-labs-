import random
import math


# ── Primality 

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

    return tuple(random.sample(primes, 2))



def euler_totient_naive(n: int) -> int:
    #Count how many numbers from 1 to n are coprime with n.
    count = 0

    for i in range(1, n + 1):
        if math.gcd(i, n) == 1:
            count += 1

    return count


def coprimes_of(n: int) -> list[int]:
    #Return all numbers in [1, n] that are coprime with n.
    coprimes = []

    for i in range(1, n + 1):
        if math.gcd(i, n) == 1:
            coprimes.append(i)

    return coprimes


# ── Display Helper 

def section(title: str) -> None:
    print(f"\n{'─' * 52}")
    print(f"  {title}")
    print(f"{'─' * 52}")


# ── Main Program 

if __name__ == "__main__":

    # Step 1: Choose two primes
    section("Step 1 — Pick Two Distinct Primes")

    low = int(input("Enter lower bound: "))
    high = int(input("Enter upper bound: "))

    p, q = pick_two_distinct_primes(low, high)

    n = p * q

    print(f"\np = {p}")
    print(f"q = {q}")
    print(f"n = p × q = {n}")

    # Step 2: Compute φ(n) using naive method
    section("Step 2 — Compute Euler Totient φ(n)")

    phi_n = euler_totient_naive(n)

    print(f"φ({n}) = {phi_n}")

    # Step 3: Show coprimes of n (can be large!)
    show = input("\nShow all coprimes of n? (y/n): ").lower()

    if show == "y":
        coprimes = coprimes_of(n)

        print(f"\nNumbers coprime with {n}:")
        print(coprimes)

        print(f"\nCount = {len(coprimes)}")
        print(f"φ({n}) = {phi_n}")

    # Step 4: Small demonstration
    section("Step 3 — Demonstration with a Small Number")

    demo = int(input("Enter a small number (e.g. 12): "))

    demo_coprimes = coprimes_of(demo)

    print(f"\nNumbers coprime with {demo}:")
    print(demo_coprimes)

    print(f"\nCount = {len(demo_coprimes)}")
    print(f"φ({demo}) = {euler_totient_naive(demo)}")