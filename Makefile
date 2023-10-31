.PHONY: test

test:
	@echo "Running tests..."
	@./compare_compilers swap.c && echo "swap.c success" || echo "swap.c failed"
	@./compare_compilers add.c && echo "add.c success" || echo "add.c failed"
	@./compare_compilers lt.c && echo "lt.c success" || echo "lt.c failed"
	@./compare_compilers swap-fib.c && echo "swap-fib.c success" || echo "swap-fib.c failed"
	@echo "All tests completed"
