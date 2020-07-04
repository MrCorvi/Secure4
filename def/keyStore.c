#include "../header/keyStore.h"


void createKeyArray() {
    // Our memory buffer will be readable and writable:
    int protection = PROT_READ | PROT_WRITE;

    // The buffer will be shared (meaning other processes can access it), but
    // anonymous (meaning third-party processes cannot obtain an address for it),
    // so only this process and its children will be able to use it:
    int visibility = MAP_SHARED | MAP_ANONYMOUS;

    // The remaining parameters to `mmap()` are not important for this use case,
    // but the manpage for `mmap` explains their purpose.
    keyArray = (char*) mmap(NULL, MAX_USERS * SIM_KEY_LEN, protection, visibility, -1, 0);

    mutex_keys = sem_open("mutex_keys", O_CREAT | O_EXCL, 0644, 1);
    if(mutex_keys == SEM_FAILED) {
        //perror("semaphore initilization");
        sem_unlink("mutex_keys");
        mutex_keys = sem_open("mutex_keys", O_CREAT | O_EXCL, 0644, 1);
        if(mutex_keys == SEM_FAILED) {
            perror("semaphore initilization");
            exit(1);
        }
    }
}

void writeKey(int id, char *key){
    //printf("Child read: %s\n",(char*) shmem);
    if(strlen(key) != SIM_KEY_LEN-1){
        printf("The given has a not valid key length: %d\n", (int)strlen(key));
        return;
    }
    //sem_wait(mutex_keys);
    memcpy(keyArray + id * SIM_KEY_LEN, key, SIM_KEY_LEN);
    //printf("Child wrote: %s\n",(char*) keyArray + id * SIM_KEY_LEN);
    sem_post(mutex_keys);
    
}


void readKey(int id, char* key){

    sem_wait(mutex_keys);
    //printf("After 1s, parent read: %s\n",(char*) keyArray + id * SIM_KEY_LEN);
    memcpy(key, keyArray + id * SIM_KEY_LEN, SIM_KEY_LEN);
    //memcpy(shmem, parent_message, sizeof(parent_message));
    sem_post(mutex_keys);
}

void clearKey(int id){
    char temp_key[SIM_KEY_LEN];
    for(int i; i<SIM_KEY_LEN; i++){
        temp_key[i] = '\0';
    }
	readKey(id, temp_key);
}
