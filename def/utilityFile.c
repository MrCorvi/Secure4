
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
    fprintf(file1, "\n%s", line);
    fclose(file1);
}

// header is row 1
int remove_row(char* filename, int row){

    if(row==1) return -1; // try to remove header

    char *line_buf = NULL;
    size_t line_buf_size = 0;
    int line_count = 0 ;
    size_t line_size;

    /* Open the file for reading */
    FILE* file1 = fopen(filename, "r");
    FILE* file2 = fopen("aux.csv", "a");
    if (!file1)
    {
        fprintf(stderr, "Error opening file '%s'\n", filename);
        return 1;
    }
    if (!file2)
    {
        fprintf(stderr, "Error opening aux file\n");
        return 1;
    }

    /* Get the first line of the file (header) with a POSIX function*/
    line_size = getline(&line_buf, &line_buf_size, file1);
    line_count++; /* Increment our line count */
    while(line_size >= 0){
        
        if(line_count != row)
            fprintf(file2, "%s", line_buf);
 
        /* Get the next line */
        line_size = getline(&line_buf, &line_buf_size, file1);   
        line_count++;
    }
    /* Free the allocated resources */
    free(line_buf);
    line_buf = NULL;
    fclose(file1);

    system("mv aux.csv activeuser.csv");
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
/*
int main(){

    char* filename = "activeuser.csv";
 
    //read_all_file(filename);
    //print_column(filename, 3);
    //append_row(filename, "ciao a tutti");  
    //remove_row(filename, 3);
}
*/

