#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sys/mman.h>
#define MAX_ALLOC 100000000
#define MIN_SPLIT 128
#define MAX_BIG 128000
struct histogram
{
};
bool validSize(size_t s);
bool isNull(void *ptr)
{
    return (ptr) == NULL;
}
bool check(void *ptr)
{
    return (ptr) == NULL;
}
bool isMinusOne(void *ptr)
{
    return ptr == (void *)(-1);
}
typedef struct MM
{
    size_t s;
    bool is_free;
    MM *next_block_pointer;
    MM *previous_block_pointer;
} MM;
size_t getRealSize(MM *m)
{
    return (m->s) - sizeof(MM);
}
class MList
{
private:
    MM *srbk_list;
    MM *mmap_list;

public:
    MList() : srbk_list(NULL), mmap_list(NULL) {}
    void addAlloc(MM *new_alloc);
    void *reallocateBlock(void *old_pointer, size_t s);
    void splitBlocks(MM *addr, size_t s);
    size_t getBlockSize(void *p);
    size_t getNumFreeBlocks();
    size_t getNumFreeBytes();
    void *allocateBlock(size_t s);
    void releaseBlock(void *p);
    void mergeBlocks(MM *previous_block_pointer, MM *current_block_pointer, bool is_free);
    size_t getNumAllocatedBlocks();
    size_t getNumAllocatedBytes();
    size_t getNumMetaDataBytes();
};
void MList::mergeBlocks(MM *previous_block_pointer, MM *current_block_pointer, bool is_free)
{
    check(previous_block_pointer);
    check(current_block_pointer);
    previous_block_pointer->s += sizeof(MM) + current_block_pointer->s;
    previous_block_pointer->next_block_pointer = current_block_pointer->next_block_pointer;
    if (!isNull(current_block_pointer->next_block_pointer))
        current_block_pointer->next_block_pointer->previous_block_pointer = current_block_pointer->previous_block_pointer;
    previous_block_pointer->is_free = is_free;
}

size_t MList::getNumAllocatedBytes()
{
    size_t sum_of_free_bytes = 0;
    MM *current_block_pointer = srbk_list;
    while (!isNull(current_block_pointer))
    {
        sum_of_free_bytes += current_block_pointer->s;
        current_block_pointer = current_block_pointer->next_block_pointer;
    }
    current_block_pointer = mmap_list;
    while (!isNull(current_block_pointer))
    {
        sum_of_free_bytes += current_block_pointer->s;
        current_block_pointer = current_block_pointer->next_block_pointer;
    }
    return sum_of_free_bytes;
}


void MList::releaseBlock(void *p)
{
    MM *current_block_pointer = (MM *)((char *)p - sizeof(MM));
    if (current_block_pointer->s >= MAX_BIG)
    {
        if (!isNull(current_block_pointer->previous_block_pointer))
            current_block_pointer->previous_block_pointer->next_block_pointer = current_block_pointer->next_block_pointer;
        if (!isNull(current_block_pointer->next_block_pointer))
            current_block_pointer->next_block_pointer->previous_block_pointer = current_block_pointer->previous_block_pointer;
        if (isNull(mmap_list))
            mmap_list = current_block_pointer->next_block_pointer;
        munmap(current_block_pointer, sizeof(MM) + current_block_pointer->s);
        return;
    }

    if (!isNull(current_block_pointer->previous_block_pointer) && current_block_pointer->previous_block_pointer->is_free)
    {
        mergeBlocks(current_block_pointer->previous_block_pointer, current_block_pointer, true);
        current_block_pointer = current_block_pointer->previous_block_pointer;
    }
    if (!isNull(current_block_pointer->next_block_pointer) && current_block_pointer->next_block_pointer->is_free)
    {
        mergeBlocks(current_block_pointer, current_block_pointer->next_block_pointer, true);
    }
    current_block_pointer->is_free = true;
}

size_t MList::getBlockSize(void *p)
{
    MM *metadata = (MM *)((char *)p - sizeof(MM));
    size_t s = getRealSize(metadata);
    s = (s % 8 != 0) ? (8 - s % 8) : s;
    return s;
}

size_t MList::getNumFreeBlocks()
{
    size_t counter_of_allocated_blocks = 0;
    MM *current_block_pointer = srbk_list;
    if (isNull(srbk_list))
    {
        return 0;
    }
    while (!isNull(current_block_pointer))
    {
        if (current_block_pointer->is_free)
            counter_of_allocated_blocks++;
        current_block_pointer = current_block_pointer->next_block_pointer;
    }
    return counter_of_allocated_blocks;
}
void *MList::allocateBlock(size_t s)
{
    s = (s % 8 != 0) ? (8 - s % 8) : s;
    if (s < MAX_BIG)
    {
        MM *previous_block_pointer = srbk_list;
        MM *current_block_pointer = srbk_list;
        while (!isNull(current_block_pointer) && (current_block_pointer->s < s || !current_block_pointer->is_free))
        {
            previous_block_pointer = current_block_pointer;
            current_block_pointer = current_block_pointer->next_block_pointer;
        }
        if (isNull(current_block_pointer))
        {
            if (!isNull(previous_block_pointer) && previous_block_pointer->is_free)
            {
                void *address_of_memory = sbrk(s - previous_block_pointer->s);
                if (isMinusOne(address_of_memory))
                {
                    return NULL;
                }
                previous_block_pointer->is_free = false;
                previous_block_pointer->s = s;
                return (void *)((char *)previous_block_pointer + sizeof(MM));
            }
            intptr_t increment = sizeof(MM) + s;
            void *address_of_memory = sbrk(increment);
            if (isMinusOne(address_of_memory))
            {
                return NULL;
            }
            *(MM *)address_of_memory = (MM){s, false, NULL, previous_block_pointer};
            if (isNull(previous_block_pointer))
            {
                srbk_list = (MM *)address_of_memory;
            }
            else
            {
                previous_block_pointer->next_block_pointer = (MM *)address_of_memory;
            }
            return (void *)((char *)address_of_memory + sizeof(MM));
        }
        else
        {
            if (current_block_pointer->s - s >= sizeof(MM) + MIN_SPLIT)
            {
                splitBlocks(current_block_pointer, s);
            }
            current_block_pointer->is_free = false;
            return (void *)(sizeof(MM) + (char *)current_block_pointer);
        }
    }
    else
    {

        void *address_of_memory = mmap(NULL, sizeof(MM) + s,
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if (address_of_memory == MAP_FAILED)
        {
            return NULL;
        }
        *(MM *)address_of_memory = (MM){s, false, mmap_list, NULL};
        if (!isNull(mmap_list))
            mmap_list->previous_block_pointer = (MM *)address_of_memory;
        mmap_list = (MM *)address_of_memory;
        return (void *)(sizeof(MM) + (char *)address_of_memory);
    }
}


void *MList::reallocateBlock(void *old_pointer, size_t s)
{
    s = (s % 8 != 0) ? (8 - s % 8) : s;
    MM *old_block_data = (MM *)((char *)old_pointer - sizeof(MM));
    MM *new_block_data = NULL;
    size_t size_of_old_block = getRealSize(old_block_data);
    size_t real_block_size = s < size_of_old_block ? s : size_of_old_block;
    void *data_to_be_allocated = NULL;
    if (s >= MAX_BIG)
    {
        if (size_of_old_block >= s)
        {
            new_block_data = old_block_data;
            return old_pointer;
        }
        else
        {
            data_to_be_allocated = allocateBlock(s);
            if (!isNull(data_to_be_allocated))
            {
                memmove(data_to_be_allocated, old_pointer, real_block_size);
                releaseBlock(old_pointer);
                return data_to_be_allocated;
            }
            else
                return NULL;
        }
    }
    if (old_block_data->s >= s)
    {
        new_block_data = old_block_data;
    }
    else if (!isNull(old_block_data->previous_block_pointer) && old_block_data->previous_block_pointer->is_free && old_block_data->previous_block_pointer->s + sizeof(MM) + old_block_data->s >= s)
    {
        mergeBlocks(old_block_data->previous_block_pointer, old_block_data, false);
        new_block_data = old_block_data->previous_block_pointer;
    }
    else if (!isNull(old_block_data->next_block_pointer) && old_block_data->next_block_pointer->is_free &&
             old_block_data->next_block_pointer->s + sizeof(MM) + old_block_data->s >= s)
    {
        mergeBlocks(old_block_data, old_block_data->next_block_pointer, false);
        new_block_data = old_block_data;
    }
    else if (!isNull(old_block_data->next_block_pointer) && !isNull(old_block_data->previous_block_pointer) &&
             old_block_data->previous_block_pointer->is_free && old_block_data->next_block_pointer->is_free &&
             old_block_data->previous_block_pointer->s + old_block_data->s + old_block_data->next_block_pointer->s + 2 * sizeof(MM))
    {
        new_block_data = old_block_data->previous_block_pointer;
        mergeBlocks(old_block_data->previous_block_pointer, old_block_data, false);
        mergeBlocks(old_block_data->previous_block_pointer, old_block_data->next_block_pointer, false);
    }
    if (!isNull(new_block_data))
    {
        if (new_block_data->s - (getRealSize(new_block_data)) >= MIN_SPLIT + sizeof(MM))
        {
            splitBlocks(new_block_data, s);
        }
        data_to_be_allocated = (void *)((char *)new_block_data + sizeof(MM));
        memmove(data_to_be_allocated, old_pointer, real_block_size);
        return data_to_be_allocated;
    }
    MM *previous_block_pointer = srbk_list;
    MM *current_block_pointer = srbk_list;

    while (!isNull(current_block_pointer) && (current_block_pointer->s < s || !current_block_pointer->is_free))
    {
        previous_block_pointer = current_block_pointer;
        current_block_pointer = current_block_pointer->next_block_pointer;
    }
    if (isNull(current_block_pointer) && previous_block_pointer == old_block_data)
    {
        void *address_of_memory = sbrk(s - previous_block_pointer->s);
        if (isMinusOne(address_of_memory))
        {
            return NULL;
        }
        previous_block_pointer->is_free = false;
        previous_block_pointer->s = s;
        return (void *)(sizeof(MM) + (char *)previous_block_pointer);
    }
    else if (isNull(current_block_pointer))
    {
        if (!isNull(previous_block_pointer) && previous_block_pointer->is_free)
        {
            void *address_of_memory = sbrk(s - previous_block_pointer->s);
            if (isMinusOne(address_of_memory))
            {
                return NULL;
            }
            previous_block_pointer->is_free = false;
            previous_block_pointer->s = s;
            data_to_be_allocated = (void *)(sizeof(MM) + (char *)previous_block_pointer);
        }
        else
        {
            intptr_t increment = s + sizeof(MM);
            void *address_of_memory = sbrk(increment);
            if (isMinusOne(address_of_memory))
            {
                return NULL;
            }
            *(MM *)address_of_memory = (MM){s, false, NULL, previous_block_pointer};
            if (isNull(previous_block_pointer))
            {
                srbk_list = (MM *)address_of_memory;
            }
            else
            {
                previous_block_pointer->next_block_pointer = (MM *)address_of_memory;
            }
            data_to_be_allocated = (void *)(sizeof(MM) + (char *)address_of_memory);
        }
    }
    else
    {
        if (current_block_pointer->s - s >= sizeof(MM) + MIN_SPLIT)
        {
            splitBlocks(current_block_pointer, s);
        }
        current_block_pointer->is_free = false;
        data_to_be_allocated = (void *)(sizeof(MM) + (char *)current_block_pointer);
    }
    if (isNull(data_to_be_allocated))
    {
        return NULL;
    }
    memmove(data_to_be_allocated, old_pointer, real_block_size);
    releaseBlock(old_pointer);
    return data_to_be_allocated;
}

size_t MList::getNumMetaDataBytes()
{
    return this->getNumAllocatedBlocks() * sizeof(MM);
}
size_t MList::getNumFreeBytes()
{
    size_t sum_of_free_bytes = 0;
    MM *current_block_pointer = srbk_list;
    if (isNull(srbk_list))
    {
        return 0;
    }
    while (!isNull(current_block_pointer))
    {
        if (current_block_pointer->is_free)
            sum_of_free_bytes += current_block_pointer->s;
        current_block_pointer = current_block_pointer->next_block_pointer;
    }
    return sum_of_free_bytes;
}

size_t MList::getNumAllocatedBlocks()
{
    size_t counter_of_allocated_blocks = 0;
    MM *current_block_pointer = srbk_list;
    while (!isNull(current_block_pointer))
    {
        counter_of_allocated_blocks++;
        current_block_pointer = current_block_pointer->next_block_pointer;
    }
    current_block_pointer = mmap_list;
    while (!isNull(current_block_pointer))
    {
        counter_of_allocated_blocks++;
        current_block_pointer = current_block_pointer->next_block_pointer;
    }
    return counter_of_allocated_blocks;
}

void MList::splitBlocks(MM *current_block_pointer, size_t s)
{
    s = (s % 8 != 0) ? (8 - s % 8) : s;
    char *block_after_split_char = (char *)current_block_pointer + sizeof(MM) + s;
    MM *metadata_after_split = (MM *)block_after_split_char;
    metadata_after_split->s = current_block_pointer->s - s - sizeof(MM);
    metadata_after_split->is_free = true;
    current_block_pointer->s = s;
    if (!isNull(current_block_pointer->next_block_pointer))
        current_block_pointer->next_block_pointer->previous_block_pointer = metadata_after_split;
    metadata_after_split->previous_block_pointer = current_block_pointer;
    metadata_after_split->next_block_pointer = current_block_pointer->next_block_pointer;
    current_block_pointer->next_block_pointer = metadata_after_split;
}
MList main_allocation_list = MList();

void *smalloc(size_t s)
{
    if (s >= MAX_ALLOC || s == 0)
    {
        return NULL;
    }
    return main_allocation_list.allocateBlock(s);
}

void *scalloc(size_t num, size_t s)
{
    s = (s % 8 != 0) ? (8 - s % 8) : s;
    size_t size_in_bytes = num * s;
    if (size_in_bytes == 0 || size_in_bytes >= MAX_ALLOC)
        return NULL;
    void *addr = main_allocation_list.allocateBlock(size_in_bytes);
    if (isNull(addr))
    {
        return NULL;
    }
    return memset(addr, 0, size_in_bytes);
}

void sfree(void *p)
{
    if (p == NULL)
    {
        return;
    }
    main_allocation_list.releaseBlock(p);
}

void *srealloc(void *old_pointer, size_t s)
{
    s = (s % 8 != 0) ? (8 - s % 8) : s;
    if (s == 0 || s >= MAX_ALLOC)
        return NULL;
    if (isNull(old_pointer))
    {
        return smalloc(s);
    }
    return main_allocation_list.reallocateBlock(old_pointer, s);
}

size_t _num_free_blocks()
{
    return main_allocation_list.getNumFreeBlocks();
}

size_t _num_free_bytes()
{
    return main_allocation_list.getNumFreeBytes();
}
size_t _num_allocated_blocks()
{
    return main_allocation_list.getNumAllocatedBlocks();
}
size_t _num_allocated_bytes()
{
    return main_allocation_list.getNumAllocatedBytes();
}
size_t _num_meta_data_bytes()
{
    return main_allocation_list.getNumMetaDataBytes();
}
int main(){
    return 0;
}
