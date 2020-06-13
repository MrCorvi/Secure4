
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

void read_all_file(char* filename );
void print_column(char* filename , int col);
void get_ID_column(char* filename, uint16_t *len, uint16_t *IDs);
void append_row(char* filename , char* line );
void remove_row(char* filename, int row);
int get_row_by_id(char* filename, int id);
const char* get_column_by_id(char* filename, int id,int col);
int remove_row_by_id(char* filename, uint32_t id);