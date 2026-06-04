import random
import math


# ── Primality ────────────────────────────────────────────────────────────────

def is_prime(n: int) -> bool:
    """Check primality using trial division."""
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
    """Return all primes within [low, high]."""
    primes = []
    for n in range(low, high + 1):
        if is_prime(n):
            primes.append(n)
    return primes


def pick_two_distinct_primes(low: int, high: int) -> tuple[int, int]:
    """Randomly pick two distinct primes from the given range."""
    primes = get_primes_in_range(low, high)
    if len(primes) < 2:
        raise ValueError("Not enough primes in range. Try a bigger range.")
    return tuple(random.sample(primes, 2))


# ── Euler's Totient ──────────────────────────────────────────────────────────

def euler_totient_naive(n: int) -> int:
    """
    Naive method: iterate through 1..n, count values where gcd(i, n) == 1.
    Time complexity: O(n log n)
    """
    count = 0
    for i in range(1, n + 1):
        if math.gcd(i, n) == 1:
            count += 1
    return count


def euler_totient_formula(n: int) -> int:
    """
    Efficient method using Euler's product formula:
        phi(n) = n * product of (1 - 1/p) for each distinct prime factor p of n

    Time complexity: O(sqrt n)
    """
    result = n
    temp = n
    p = 2

    while p * p <= temp:
        if temp % p == 0:
            while temp % p == 0:
                temp //= p
            result -= result // p
        p += 1

    if temp > 1:
        result -= result // temp

    return result


def totient_of_prime(p: int) -> int:
    """Special case: if p is prime, phi(p) = p - 1."""
    return p - 1


def totient_of_prime_product(p: int, q: int) -> int:
    """Special case n = p*q (both prime): phi(p*q) = (p-1)(q-1)."""
    return (p - 1) * (q - 1)


def coprimes_of(n: int) -> list[int]:
    """Return the list of integers in [1, n] that are coprime with n."""
    return [i for i in range(1, n + 1) if math.gcd(i, n) == 1]


# ── Display helpers ──────────────────────────────────────────────────────────

def section(title: str) -> None:
    print(f"\n{'─' * 52}")
    print(f"  {title}")
    print(f"{'─' * 52}")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    # Step 1 — pick p and q
    section("Step 1 — Pick two distinct primes")
    LOW  = int(input("  Enter lower bound: "))
    HIGH = int(input("  Enter upper bound: "))

    p, q = pick_two_distinct_primes(LOW, HIGH)
    n = p * q

    print(f"\n  p = {p}")
    print(f"  q = {q}")
    print(f"  n = p x q = {n}")

    # Step 2 — phi(p) and phi(q) individually
    section("Step 2 — phi(p) and phi(q)   [prime rule: phi(prime) = prime - 1]")
    print(f"  phi({p}) = {p} - 1 = {totient_of_prime(p)}")
    print(f"  phi({q}) = {q} - 1 = {totient_of_prime(q)}")

    # Step 3 — phi(n) via three methods
    section("Step 3 — phi(n) = phi(p x q) = (p-1)(q-1)")
    phi_pq       = totient_of_prime_product(p, q)
    phi_naive    = euler_totient_naive(n)
    phi_formula  = euler_totient_formula(n)

    print(f"  phi({n})  via (p-1)(q-1)      = ({p}-1) x ({q}-1) = {phi_pq}")
    print(f"  phi({n})  via naive GCD count  = {phi_naive}")
    print(f"  phi({n})  via product formula  = {phi_formula}")
    print(f"\n  All three methods agree: {phi_pq == phi_naive == phi_formula}")

    # Step 4 — illustrate coprimes for a small number
    section("Step 4 — Illustration on a small number")
    demo = int(input("  Enter a small number to list its coprimes (e.g. 12): "))
    cops = coprimes_of(demo)
    print(f"\n  Numbers in [1, {demo}] coprime with {demo}:")
    print(f"  {cops}")
    print(f"\n  Count  = phi({demo}) = {len(cops)}")
    print(f"  Formula check: phi({demo}) = {euler_totient_formula(demo)}")