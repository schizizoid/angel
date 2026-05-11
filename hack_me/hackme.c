#include <stdio.h>
#include <unistd.h>

int main() {
    float number = 40;

    volatile char gibberish[2500000];
    for(int i = 0; i < 2500000; i++) {
        gibberish[i] = i * 37 + 13;
    }

    while (true)
    {
        printf("Hack me! %f %i %p\n", number, getpid(), &number);
        sleep(3);
        number += 1.0f;
    }
    return 0;
}