#include <stdio.h>
#include <unistd.h>

int main() {
    float number = 40;
    while (true)
    {
        printf("Hack me! %f %i %p\n", number, getpid(), &number);
        sleep(3);
        number += 1.0f;
    }
    return 0;
}