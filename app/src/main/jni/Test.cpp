//
// Created by Apple on 2021/5/20.
//

#include <cstdlib>
#include "Test.h"

int Test::getTestData() {
    volatile int* p = NULL;
    *p = 1;
    return 0;
}