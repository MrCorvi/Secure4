#include<stdint.h> 
#include<sys/types.h>
#include"../header/utilityFile.h"

// not used but useful to understand
void print_all_fields(char* tmp){

    //printf("%s", tmp);
    char* pch = strtok(tmp, ","); // splits in token with comma delimiter
    while(pch != NULL){

        printf("%s\n", pch);
        pch = strtok(NULL, ",\n"); // in subsequent calls it expects a null pointer
                                 // and use the position right after the end of 
                                 // the last token. NULL indicate to continue
                                 // tokenizing the string you passed in first
    }
}

const char* get_field(char* tmp, int col){

    const char* tok;
    // when tmp finish, *tok=0(false)
    for (tok = strtok(tmp, ",");  tok && *tok ; tok = strtok(NULL, ",\n")){
        col--;
        if (col==0)
            return tok;
    }
    return NULL;
}

void get_ID_column(char* filename, uint16_t *dim, uint16_t *IDs){
    FILE * fp;
    char * line = NULL, *id, *token=",";
    size_t len = 0;
    int read;
    uint16_t i=0;

    fp = fopen(filename, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    getline(&line, &len, fp);

    while ((read = getline(&line, &len, fp)) != -1) {
        //printf("%s\n\n", line);
        IDs[i] = (uint16_t)atoi(strtok(line, token));
        //printf("%d\n", IDs[i]);
        i++;
    }
    *dim = i;

    fclose(fp);
    if (line)
        free(line);
}

void append_row(char* filename, char* line){

    FILE* file1 = fopen(filename, "a");
    fprintf(file1, "%s\n", line);
    fclose(file1);
}

// header is row 1
void remove_row(char* filename, int row){

    if(row==1) return; // try to remove header

    char *line_buf = NULL;
    size_t line_buf_size = 0;
    int line_count = 0 ;
    ssize_t line_size;

    /* Open the file for reading */
    FILE* file1 = fopen(filename, "r");
    FILE* file2 = fopen("aux.csv", "a");
    if (!file1)
    {
        fprintf(stderr, "Error opening file '%s'\n", filename);
        return;
    }
    if (!file2)
    {
        fprintf(stderr, "Error opening aux file\n");
        return;
    }

    /* Get the first line of the file (header) with a POSIX function*/
    line_size = getline(&line_buf, &line_buf_size, file1);
    line_count++; /* Increment our line count */
    //printf("                                    %d   %s\n", (int)line_size, line_buf);
    while(line_size >= 0){
        
        if(line_count != row)
            fprintf(file2, "%s", line_buf);
 
        // Get the next line 
        line_size = getline(&line_buf, &line_buf_size, file1); 
        //printf("                                    %d   %s   %d %d\n", (int)line_size, line_buf, line_count, row);
        line_count++;
    }
    /* Free the allocated resources */
    free(line_buf);
    line_buf = NULL;
    fclose(file1);
    fclose(file2);

    system("mv aux.csv loggedUser.csv");
}

void read_all_file(char* filename){

    FILE *file1 = fopen(filename, "r");
    char buffer[1024];

    while(fgets(buffer, 1024, file1)){

        char* tmp = strdup(buffer); //copy line
        printf("%s", tmp);
        free(tmp);
    }
    fclose(file1);

}

void print_column(char* filename, int col){
   
    FILE* file1 = fopen(filename,"r");
    char buffer[1024];

    while(fgets(buffer, 1024, file1)){

        char* p = strchr(buffer, '\n');
        char* tmp = strdup(buffer); //copy line
        //print_all_fields(tmp);
        //printf("%s", tmp);
        printf("%s\n", get_field(tmp, col));
        free(tmp);
    }
    fclose(file1);

}

int get_row_by_id(char* filename, int id){

    FILE* file1 = fopen(filename,"r");
    char buffer[1024];
    char snum[5];
    int count=0;

    sprintf(snum, "%d", id);

    while(fgets(buffer, 1024, file1)){
        char* p = strchr(buffer, '\n');
        char* tmp = strdup(buffer);
        
        if(strcmp(get_field(tmp,1),snum)==0)
            return count+1;
        free(tmp);
        count++;
    }
    fclose(file1);

    return -1;
}

const char* get_column_by_id(char* filename, int id,int col){

    FILE* file1 = fopen(filename,"r");
    char buffer[1024];
    char snum[5];

    sprintf(snum, "%d", id);
    printf("SNUM: %s ID:%d\n", snum, id);

    while(fgets(buffer, 1024, file1)){
        char* tmp = strdup(buffer);
        if(strcmp(get_field(tmp,1),snum)==0){
            return get_field(buffer,col);
        }
        free(tmp);
    }
    fclose(file1);
    
    return NULL;
}

void get_buf_column_by_id(char* filename, int id,int col, char* retBuffer){

    FILE* file1 = fopen(filename,"r");
    char buffer[1024];
    char snum[5];

    sprintf(snum, "%d", id);
    printf("SNUM: %s ID:%d\n", snum, id);

    while(fgets(buffer, 1024, file1)){
        char* tmp = strdup(buffer);
        //printf("Ehiii tmp %s get_field a col %d: %s \n",tmp,col,get_field(tmp,col));
        if(strcmp(get_field(tmp,1),snum)==0){
            strcpy(retBuffer, get_field(buffer,col));
            return;
        }
        free(tmp);
    }
    fclose(file1);
}


int remove_row_by_id(char* filename, uint32_t id){
    char buffer[1024];
    int row_num;
    //remove old row version
    row_num = get_row_by_id(filename, id);
    //if not pack err
    if(row_num==-1){
        printf("ID non presente!\n");
        return 0;
    }
    printf("rimuovo riga %d \n", row_num);
    remove_row(filename, row_num);
}


int update_row(char* filename, uint32_t my_id, const char ip[], uint16_t cl_port, uint32_t nonce){
    char buffer[1024];
    //char key[300];
    int row_num, ret = 1;

    //get key
    //sprintf(key, "%s", get_column_by_id(filename, my_id, 5));
    
    //remove old row version
    row_num = get_row_by_id(filename, my_id);
    //if not pack err
    if(row_num==-1){
        printf("ID non presente!\n");
        ret = 0;
    }
    printf("rimuovo riga %d \n", row_num);
    remove_row(filename, row_num);

    //append new row version
    //sprintf(buffer,"%d,%s,%d,%d,%s", my_id, ip, cl_port, nonce, key);
    sprintf(buffer,"%d,%s,%d,%d", my_id, ip, cl_port, nonce);
    printf("                %s\n",buffer);
    append_row(filename, buffer);
    return ret;
}

