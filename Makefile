.PHONY: test

test:
	@echo "Running tests..."
	@./compare_compilers swap.c && echo "swap.c success" || echo "swap.c failed"
	@./compare_compilers add.c && echo "add.c success" || echo "add.c failed"
	@echo "All tests completed"
