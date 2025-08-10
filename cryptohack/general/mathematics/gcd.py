def euclidean_gcd(a: int, b: int) -> int:
    """Calculate the GCD of two integers using the Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)

print(euclidean_gcd(a=66528,b=52920 ))