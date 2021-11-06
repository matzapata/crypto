
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#if PRIMES_SRC == HEADER
#include "primes.h"
#endif

int8_t buffer[1024];
const int MAX_DIGITS = 50;
int i, j = 0;

struct public_key_class
{
  int64_t  modulus;
  int64_t  exponent;
};

struct private_key_class
{
  int64_t  modulus;
  int64_t  exponent;
};

// This should totally be in the math library.
int64_t  gcd(int64_t  a, int64_t  b)
{
  int64_t  c;
  while (a != 0)
  {
    c = a;
    a = b % a;
    b = c;
  }
  return b;
}

int64_t  ExtEuclid(int64_t  a, int64_t  b)
{
  int64_t  x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
  while (a != 0)
  {
    q = gcd / a;
    r = gcd % a;
    m = x - u * q;
    n = y - v * q;
    gcd = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }
  return y;
}
static inline int64_t  modmult(int64_t  a, int64_t  b, int64_t  mod)
{
  // this is necessary since we will be dividing by a
  if (a == 0)
  {
    return 0;
  }
  register int64_t  product = a * b;
  //if multiplication does not overflow, we can use it
  if (product / a == b)
  {
    return product % mod;
  }
  // if a % 2 == 1 i. e. a >> 1 is not a / 2
  if (a & 1)
  {
    product = modmult((a >> 1), b, mod);
    if ((product << 1) > product)
    {
      return (((product << 1) % mod) + b) % mod;
    }
  }
  //implicit else
  product = modmult((a >> 1), b, mod);
  if ((product << 1) > product)
  {
    return (product << 1) % mod;
  }
  //implicit else: this is about 10x slower than the code above, but it will not overflow
  int64_t  sum;
  sum = 0;
  while (b > 0)
  {
    if (b & 1)
      sum = (sum + a) % mod;
    a = (2 * a) % mod;
    b >>= 1;
  }
  return sum;
}
int64_t  rsa_modExp(int64_t  b, int64_t  e, int64_t  m)
{
  int64_t  product;
  product = 1;
  if (b < 0 || e < 0 || m <= 0)
  {
    return -1;
  }
  b = b % m;
  while (e > 0)
  {
    if (e & 1)
    {
      product = modmult(product, b, m);
    }
    b = modmult(b, b, m);
    e >>= 1;
  }
  return product;
}
// Calling this function will generate a public and private key and store them in the pointers
// it is given.
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv, int8_t *PRIME_SOURCE_FILE)
{
#if PRIMES_SRC == TXT
  FILE *primes_list;
  if (!(primes_list = fopen(PRIME_SOURCE_FILE, "r")))
  {
    fprintf(stderr, "Problem reading %s\n", PRIME_SOURCE_FILE);
    exit(1);
  }

  // count number of primes in the list
  int64_t  prime_count = 0;
  do
  {
    int bytes_read = fread(buffer, 1, sizeof(buffer) - 1, primes_list);
    buffer[bytes_read] = '\0';
    for (i = 0; buffer[i]; i++)
    {
      if (buffer[i] == '\n')
      {
        prime_count++;
      }
    }
  } while (feof(primes_list) == 0);

#else
  // int64_t  prime_count = 37;
  int64_t  prime_count = sizeof(primes) / sizeof(primes[0]);
#endif

  // choose random primes from the list, store them as p,q
  int64_t  p = 0;
  int64_t  q = 0;

  //values of e should be sufficiently large to protect against naive attacks
  int64_t  e = (2 << 16) + 1;
  int64_t  d = 0;
  int64_t  max = 0;
  int64_t  phi_max = 0;

#if PRIMES_SRC == TXT
  int8_t prime_buffer[MAX_DIGITS];
#endif

  srand(time(NULL));

  do
  {
    // a and b are the positions of p and q in the list
    int a = (double)rand() * (prime_count + 1) / (RAND_MAX + 1.0);
    int b = (double)rand() * (prime_count + 1) / (RAND_MAX + 1.0);

#if PRIMES_SRC == TXT
    // here we find the prime at position a, store it as p
    rewind(primes_list);
    for (i = 0; i < a + 1; i++)
    {
      for (j = 0; j < MAX_DIGITS; j++)
      {
        prime_buffer[j] = 0;
      }
      fgets(prime_buffer, sizeof(prime_buffer) - 1, primes_list);
    }
    p = atol(prime_buffer);
#else
    p = (long)primes[a];
#endif

#if PRIMES_SRC == TXT
    // here we find the prime at position b, store it as q
    rewind(primes_list);
    for (i = 0; i < b + 1; i++)
    {
      for (j = 0; j < MAX_DIGITS; j++)
      {
        prime_buffer[j] = 0;
      }
      fgets(prime_buffer, sizeof(prime_buffer) - 1, primes_list);
    }
    q = atol(prime_buffer);
#else
    q = (long)primes[b];
#endif

    max = p * q;
    phi_max = (p - 1) * (q - 1);
  } while (!(p && q) || (p == q) || (gcd(phi_max, e) != 1));

  // Next, we need to choose a,b, so that a*max+b*e = gcd(max,e). We actually only need b
  // here, and in keeping with the usual notation of RSA we'll call it d. We'd also like
  // to make sure we get a representation of d as positive, hence the while loop.
  d = ExtEuclid(phi_max, e);
  while (d < 0)
  {
    d = d + phi_max;
  }

  // printf("primes are %lld and %lld\n", (int64_t )p, (int64_t )q);
  // We now store the public / private keys in the appropriate structs
  pub->modulus = max;
  pub->exponent = e;

  priv->modulus = max;
  priv->exponent = d;
}

int64_t  *rsa_encrypt(const int8_t *message, const unsigned long message_size,
                       const struct public_key_class *pub)
{
  int64_t  *encrypted = malloc(sizeof(int64_t ) * message_size);
  if (encrypted == NULL)
  {
    fprintf(stderr, "Error: Heap allocation failed.\n");
    return NULL;
  }
  int64_t  i = 0;
  for (i = 0; i < message_size; i++)
  {
    if ((encrypted[i] = rsa_modExp(message[i], pub->exponent, pub->modulus)) == -1)
      return NULL;
  }
  return encrypted;
}

int8_t *rsa_decrypt(const int64_t  *message,
                  const unsigned long message_size,
                  const struct private_key_class *priv)
{
  if (message_size % sizeof(int64_t ) != 0)
  {
    fprintf(stderr,
            "Error: message_size is not divisible by %d, so cannot be output of rsa_encrypt\n", (int)sizeof(int64_t ));
    return NULL;
  }
  // We allocate space to do the decryption (temp) and space for the output as a int8_t array
  // (decrypted)
  int8_t *decrypted = malloc(message_size / sizeof(int64_t ));
  int8_t *temp = malloc(message_size);
  if ((decrypted == NULL) || (temp == NULL))
  {
    fprintf(stderr,
            "Error: Heap allocation failed.\n");
    return NULL;
  }
  // Now we go through each 8-byte chunk and decrypt it.
  int64_t  i = 0;
  for (i = 0; i < message_size / 8; i++)
  {
    if ((temp[i] = rsa_modExp(message[i], priv->exponent, priv->modulus)) == -1)
    {
      free(temp);
      return NULL;
    }
  }
  // The result should be a number in the int8_t range, which gives back the original byte.
  // We put that into decrypted, then return.
  for (i = 0; i < message_size / 8; i++)
  {
    decrypted[i] = temp[i];
  }
  free(temp);
  return decrypted;
}
