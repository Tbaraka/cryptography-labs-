#include <iostream>
#include <cstdio>
#include <random>

using namespace std;

// Function to compute a^m mod n using fast exponentiation
int compute(int a, int m, int n)
{
    int r;
    int y = 1;

    while (m > 0)
    {
        r = m % 2;

        if (r == 1)
            y = (y * a) % n;

        a = (a * a) % n;
        m = m / 2;
    }

    return y;
}

// Diffie-Hellman Key Exchange
int main()
{
    int p = 23; // Prime modulus
    int g = 5;  // Generator

    int a, b;   // Private keys
    int A, B;   // Public keys

    // Random number generator
    random_device rd;
    mt19937 gen(rd());

    // Generate random private keys between 1 and p-2
    uniform_int_distribution<> dist(1, p - 2);

    a = dist(gen); // Alice's private key
    b = dist(gen); // Bob's private key

    // Generate public keys
    A = compute(g, a, p);
    B = compute(g, b, p);

    // Compute shared secret keys
    int keyA = compute(B, a, p);
    int keyB = compute(A, b, p);

    // Display results
    cout << "Prime (p): " << p << endl;
    cout << "Generator (g): " << g << endl;

    cout << "\nAlice Private Key: " << a << endl;
    cout << "Alice Public Key: " << A << endl;

    cout << "\nBob Private Key: " << b << endl;
    cout << "Bob Public Key: " << B << endl;

    cout << "\nAlice's Secret Key: " << keyA << endl;
    cout << "Bob's Secret Key: " << keyB << endl;

    if (keyA == keyB)
        cout << "\nShared Secret Established Successfully!" << endl;
    else
        cout << "\nKey Exchange Failed!" << endl;

    return 0;
}