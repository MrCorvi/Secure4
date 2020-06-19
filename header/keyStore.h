#include <stdio.h> 
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"message.h"
#endif

char *keyArray;
sem_t *mutex_keys;

void createKeyArray();

void writeKey(int id, char *key);

void readKey(int id, char* key);