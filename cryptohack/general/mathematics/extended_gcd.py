def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean Algorithm to find integers x and y such that:
    a * x + b * y = gcd(a, b)

    :param a: First integer
    :param b: Second integer
    :return: A tuple (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

p=26513
q=32321
gcd, x, y = extended_gcd(p, q)
print(f"GCD: {gcd}, x: {x}, y: {y}")
print(min(x, y))