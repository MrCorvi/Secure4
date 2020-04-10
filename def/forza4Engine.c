
#include <stdio.h>

#include "../header/forza4Engine.h"

int map [MAP_WIDTH][MAP_HEIGHT];

void setup(){
    for(int i=0; i<MAP_HEIGHT; i++){
        for (int j = 0; j < MAP_WIDTH; j++){
            map[j][i] = VOID;
        }
    }
    printf("GAME START!\nInput 9 if you want to exit");
}

void renderMap(){
    printf("\n");
    for(int i=0; i<=MAP_HEIGHT; i++){
        for (int j = 0; j < MAP_WIDTH; j++){
            if(i == MAP_HEIGHT){
                printf(" %d ", j);
                continue;
            }
            if(map[j][i] == VOID){
                printf(" . ");
            }else if(map[j][i] == PLAYER_LOCAL){
                printf(" X ");
            }else{
                printf(" O ");
            }
        }
        printf("\n\n");
    }
}

//Return FALSE if colum is full
int addDisk(int addCol, int player){
    for (int i = MAP_HEIGHT-1; i >= 0; i--){
        if(map[addCol][i] == VOID){
            map[addCol][i] = player;
            return TRUE;
        }
    }
    return FALSE;
}

int check4Line(int *winPlayer){
    int checkMaps[3][MAP_WIDTH][MAP_WIDTH];
    for(int i=0; i<MAP_WIDTH; i++){
        for(int j=0; j<MAP_HEIGHT; j++){
            //0: check 4 vertical
            checkMaps[0][i][j] = map[i][j];
            //1: check 4 left oblique
            checkMaps[1][i][j] = map[(i+j)%MAP_WIDTH][j];
            //2: check 4 left oblique
            //printf("%d", (i+MAP_WIDTH-j)%MAP_WIDTH);
            checkMaps[2][i][j] = map[(i+MAP_WIDTH-j)%MAP_WIDTH][j];
        }
        //printf("\n");
    }
    
    int counter = 0;
    int lastCell = VOID;
    //check orizontal lines
    for(int j=0; j<MAP_HEIGHT; j++){
        for(int i=0; i<MAP_WIDTH; i++){
            if(checkMaps[0][i][j] != VOID){
                if(counter > 0 && lastCell == checkMaps[0][i][j]){
                    counter++;
                    //If more of 4, win
                    if(counter >= 4){
                        (*winPlayer) = checkMaps[0][i][j];
                        return TRUE;
                    }
                }else{
                    counter = 1;
                }
            }else{
                counter = 0;
            }
            lastCell = checkMaps[0][i][j];
        }
        counter = 0;
    }

    //Check vertica-oblique lines
    for(int k = 0; k < 3; k++){
        for(int i=0; i<MAP_WIDTH; i++){
            for(int j=0; j<MAP_HEIGHT; j++){
                if(checkMaps[k][i][j] != VOID){
                    if(counter > 0 && lastCell == checkMaps[k][i][j]){
                        counter++;
                        //If more of 4, win
                        if(counter >= 4){
                            (*winPlayer) = checkMaps[k][i][j];
                            return TRUE;
                        }
                    }else{
                        counter = 1;
                    }
                }else{
                    counter = 0;
                }
                lastCell = checkMaps[k][i][j];
                //if(k == 2)
                //    printf("%d",counter);
            }
            counter = 0;
            //if(k == 2)
            //    printf("\n");
        }
    }

    return FALSE;
}

int update(){
    int command;
    int check;
    /***************
    //LOCAL PLAYER//
    ***************/
    do{ 
        printf("Input the column where you want to add a disk: ");
        scanf("%d", &command);
        printf("\n");

        //Check if the input is valid
        if(command < 0 || command >= MAP_WIDTH){
            printf("\033[0;31m"); 
            printf("%d is not a valid colum\n", command);
            printf("\033[0m"); 
            continue;
        }
        check = addDisk(command, PLAYER_LOCAL);
        if(check == FALSE){
            printf("\033[0;31m"); 
            printf("The colum %d is full, try an other one\n", command);
            printf("\033[0m"); 
            continue;
        }
    }while(check == FALSE);

    int winPlayer;
    int win = check4Line(&winPlayer);
    if(win == TRUE){
        printf("\033[1;32m");
        if(winPlayer == PLAYER_LOCAL)
            printf("YOU WIN !!! \n");
        else
            printf("HOST PLAYER WIN !!! \n");
        printf("\033[0m"); 
        return FALSE;
    }
    if(command == 9)
        return FALSE;
    


    /***************
    //HOST PLAYER //
    ***************/
    int hostCommand;
    do{
        renderMap();
        printf("Waiting for host move...");
        //For now we tke a local input
        scanf("%d", &hostCommand);
        printf("\n");

        //will need to add waiting socket here !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        check = addDisk(hostCommand, PLAYER_HOST);

        
    }while(check == FALSE);

    win = check4Line(&winPlayer);
    if(win == TRUE){
        printf("\033[1;32m");
        if(winPlayer == PLAYER_LOCAL)
            printf("YOU WIN !!! \n");
        else
            printf("HOST PLAYER WIN !!! \n");
        printf("\033[0m"); 
        return FALSE;
    }
    if(hostCommand == 9)
        return FALSE;
    return TRUE;
}





void forza4Engine(){
    int goOn = TRUE;
    setup();
    while(goOn == TRUE){
        renderMap();
        goOn = update();
    }
    renderMap();
}