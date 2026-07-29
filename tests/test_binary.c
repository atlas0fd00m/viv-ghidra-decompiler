/*
 * Test binary for the Vivisect-Ghidra bridge integration test.
 *
 * This program contains functions with different complexity levels:
 * - simple_add: basic arithmetic (no branches)
 * - loop_sum: loop with accumulation
 * - conditional: branch with comparison
 * - memory_ops: stack memory reads and writes
 * - call_chain: function calls with arguments
 *
 * Compile: gcc -o test_binary test_binary.c -no-pie -O0
 * The -no-pie and -O0 flags ensure addresses are predictable and
 * the symbolik translator has straightforward instructions to work with.
 */

#include <stdio.h>
#include <string.h>

/* Simple arithmetic — no branches, no memory */
int simple_add(int a, int b) {
    return a + b;
}

/* Loop with accumulation — tests branch + memory (stack) */
int loop_sum(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += i;
    }
    return sum;
}

/* Conditional branch — tests constraint translation */
int conditional(int x) {
    if (x > 10) {
        return x * 2;
    } else {
        return x + 10;
    }
}

/* Memory operations — tests LOAD/STORE p-code */
void memory_ops(int *arr, int n) {
    for (int i = 0; i < n; i++) {
        arr[i] = arr[i] * 2 + 1;
    }
}

/* Call chain — tests CALL p-code */
int call_chain(int a, int b) {
    int s = simple_add(a, b);
    return conditional(s);
}

/* Main — calls all the above */
int main(int argc, char **argv) {
    int result = 0;

    result += simple_add(3, 4);           // 7
    result += loop_sum(10);               // 45
    result += conditional(5);             // 15
    result += conditional(20);            // 40
    result += call_chain(3, 4);           // conditional(7) = 17

    int arr[5] = {1, 2, 3, 4, 5};
    memory_ops(arr, 5);
    // arr is now [3, 5, 7, 9, 11]
    result += arr[0] + arr[4];            // 14

    printf("Result: %d\n", result);      // 7+45+15+40+17+14 = 138
    return result;                        // 138
}