
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

void read_all_file(char* filename );
void print_column(char* filename , int col);
void get_ID_column(char* filename, uint16_t *len, uint16_t *IDs);
void append_row(char* filename , char* line );
int remove_row(char* filename, int row);