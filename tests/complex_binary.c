/*
 * Complex test binary for stress-testing the bridge.
 * Contains: function pointers, structs, strings, global data,
 * nested calls, switch-like patterns, and recursion.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// ─── Structs ───
typedef struct {
    int id;
    char name[32];
    int active;
} Record;

// ─── Global data ───
Record records[3] = {
    {1, "alpha", 1},
    {2, "beta", 0},
    {3, "gamma", 1},
};

// ─── Function pointer table ───
typedef int (*op_func)(int, int);

int op_add(int a, int b) { return a + b; }
int op_sub(int a, int b) { return a - b; }
int op_mul(int a, int b) { return a * b; }

op_func ops[] = { op_add, op_sub, op_mul };

// ─── Recursion ───
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// ─── Switch-like pattern ───
int dispatch(int op_id, int a, int b) {
    if (op_id < 0 || op_id > 2) return -1;
    return ops[op_id](a, b);
}

// ─── String operations ───
int count_active(void) {
    int count = 0;
    for (int i = 0; i < 3; i++) {
        if (records[i].active) {
            count++;
            printf("Active: %s (id=%d)\n", records[i].name, records[i].id);
        }
    }
    return count;
}

// ─── Struct manipulation ───
void deactivate(Record *r) {
    r->active = 0;
}

void deactivate_all(void) {
    for (int i = 0; i < 3; i++) {
        deactivate(&records[i]);
    }
}

// ─── Main ───
int main(int argc, char **argv) {
    int result = 0;

    // Function pointer dispatch
    result += dispatch(0, 10, 3);   // 13
    result += dispatch(1, 10, 3);   // 7
    result += dispatch(2, 10, 3);   // 30

    // Recursion
    result += factorial(5);          // 120

    // String/struct operations
    result += count_active();       // 2

    // Deactivate and count again
    deactivate_all();
    result += count_active();       // 0

    printf("Result: %d\n", result); // 13+7+30+120+2+0 = 172
    return result;
}