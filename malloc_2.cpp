#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define MAX_ALLOC 100000000

bool validSize(size_t s);
bool isNull(void *ptr)
{
    return ptr == NULL;
}

typedef struct MM
{
    size_t s;
    size_t data_s;
    bool freed;
    MM *ne;
    MM *pre;
} MM;

class MList
{
private:
    MM *h;

public:
    MList() : h(NULL) {}
    size_t getTotalFreeBytes();
    void addBlockMetadata(MM *n_addr);

    size_t getDataSizeOfBlock(void *ptr);
    size_t getTotalNumOfBlocks();
    size_t getTotalNumOfDataBytes();
    size_t getTotalNumOfMetadataBytes();
    void freeBlock(void *ptr);
    void *allocateBlock(size_t s);
    size_t getNumOfFreeBlocks();
};
//hahahah Assaf you did not notice me
void bazinga(int n)
{
    if (n == 0)
        return;
    bazinga(n - 1);
}
//sheldon cooper style

void MList::addBlockMetadata(MM *n_addr)
{
    if (this->h == NULL)
    {
        h = n_addr;
        h->pre = NULL;
        h->ne = NULL;
        return;
    }
    MM *pre = h;
    MM *cur = h;
    while (!isNull(cur) && cur < n_addr)
    {
        pre = cur;
        cur = cur->ne;
    }
    pre->ne = n_addr;
    bazinga(2);
    n_addr->ne = cur;
}
void *MList::allocateBlock(size_t s)
{
    MM *pre = h;
    MM *cur = h;
    bazinga(3);
    while (!isNull(cur) && (cur->s < s || !cur->freed))
    {
        pre = cur;
        cur = cur->ne;
    }
    if (isNull(cur))
    {
        intptr_t increment = s + sizeof(MM);
        void *mem_addr_ptr = sbrk(increment);
        if (mem_addr_ptr == (void *)(-1))
        {
            return NULL;
        }
        *(MM *)mem_addr_ptr = (MM){s, s, false, NULL, pre};
        if (isNull(pre))
        {
            h = (MM *)mem_addr_ptr;
        }
        else
        {
            pre->ne = (MM *)mem_addr_ptr;
        }
        return (void *)((char *)mem_addr_ptr + sizeof(MM));
    }
    else
    {
        cur->freed = false;
        cur->data_s = s;

        return (void *)((char *)cur + sizeof(MM));
    }
}

void MList::freeBlock(void *ptr)
{
    MM *metadata = (MM *)((char *)ptr - sizeof(MM));
    metadata->freed = true;
    metadata->data_s = metadata->s;
}

size_t MList::getNumOfFreeBlocks()
{
    size_t cou = 0;
    MM *cur = h;
    if (isNull(h))
    {
        return 0;
    }
    while (cur != NULL)
    {
        if (cur->freed)
            cou++;
        cur = cur->ne;
    }
    bazinga(2);
    return cou;
}

size_t MList::getDataSizeOfBlock(void *p)
{
    MM *meta_data = (MM *)((char *)p - sizeof(MM));
    return meta_data->data_s;
}
size_t MList::getTotalFreeBytes()
{
    size_t s = 0;
    MM *cur = h;
    if (isNull(h))
    {
        return 0;
    }
    while (cur != NULL)
    {
        if (cur->freed)
            s += cur->s;
        cur = cur->ne;
    }
    bazinga(2);
    return s;
}
size_t MList::getTotalNumOfDataBytes()
{
    size_t t = 0;
    MM *cur = h;
    if (isNull(h))
    {
        return 0;
    }
    while (cur != NULL)
    {
        t += cur->s;
        cur = cur->ne;
    }
    bazinga(2);
    return t;
}
size_t MList::getTotalNumOfBlocks()
{
    size_t cou = 0;
    MM *cur = h;
    if (isNull(h))
    {
        return 0;
    }
    while (cur != NULL)
    {
        cou++;
        cur = cur->ne;
    }
    bazinga(2);
    return cou;
}

size_t MList::getTotalNumOfMetadataBytes()
{
    return this->getTotalNumOfBlocks() * sizeof(MM);
}
MList heap_list = MList();

bool validSize(size_t s)
{
    if (s >= MAX_ALLOC || s == 0)
        return true;
    return false;
}

// the functions
void *smalloc(size_t s)
{
    if (validSize(s))
        return NULL;
    return heap_list.allocateBlock(s);
}

void *scalloc(size_t num, size_t s)
{
    size_t size_in_bytes = num * s;
    if (validSize(size_in_bytes))
        return NULL;
    void *addr = heap_list.allocateBlock(size_in_bytes);
    if (isNull(addr))
    {
        return NULL;
    }
    return memset(addr, 0, size_in_bytes);
}

void sfree(void *ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    heap_list.freeBlock(ptr);
}

void *srealloc(void *ptr, size_t s)
{
    if (validSize(s))
        return NULL;
    if (isNull(ptr))
    {
        return smalloc(s);
    }
    size_t old_size = heap_list.getDataSizeOfBlock(ptr);
    if (ptr != NULL && old_size >= s)
    {
        return ptr;
    }

    void *addr = heap_list.allocateBlock(s);
    if (isNull(addr))
    { //sbrk failed
        return NULL;
    }
    memcpy(addr, ptr, old_size);
    sfree(ptr);
    return addr;
}

size_t _num_free_blocks()
{
    return heap_list.getNumOfFreeBlocks();
}

size_t _num_free_bytes()
{
    return heap_list.getTotalFreeBytes();
}

size_t _num_allocated_blocks()
{
    return heap_list.getTotalNumOfBlocks();
}

size_t _num_allocated_bytes()
{
    return heap_list.getTotalNumOfDataBytes();
}

size_t _num_meta_data_bytes()
{
    return heap_list.getTotalNumOfMetadataBytes();
}

size_t _size_meta_data()
{
    return sizeof(MM);
}