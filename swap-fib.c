int swap(int* a, int* b) {
  int t;
  t = *a; *a = *b; *b = t;
  return t;
}

int fib(int n) {
  int a, b;
  for (a = b = 1; n > 2; n = n - 1) {
    swap(&a, &b);
    b = b + a;
  }
  return b;
}

int main() {
  return fib(10); // 55
}
