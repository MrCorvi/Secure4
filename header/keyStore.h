#include <stdio.h> 
#include <stdlib.h>
#include <sys/mman.h>


void writeKey(int id);

void readKey(int id);

void* create_shared_memory(size_t size);