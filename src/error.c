#include "error.h"
#include <stdlib.h>      /* exit() */
#include <stdio.h>       /* perror() */

void
panic(const char *s)
{
    perror(s);
    exit(1);
}