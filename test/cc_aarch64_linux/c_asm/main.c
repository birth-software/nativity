extern int foo();
#include <assert.h>
int main()
{
    assert(foo() == 42);
    return 0;
}
