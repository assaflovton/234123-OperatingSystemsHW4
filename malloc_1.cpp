#include <unistd.h>
#define MAX_SIZE 100000000
void* smalloc(size_t s);
//part 1 malloc
void* smalloc(size_t s){
    if( s > MAX_SIZE || s==0){
        return NULL;
    }
    void* ptr_returned = sbrk(s);
    if(ptr_returned == (void*)-1)
    {
        return NULL;
    }
    return ptr_returned;
}