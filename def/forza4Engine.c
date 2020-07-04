
#include "../header/forza4Engine.h"

int map [MAP_WIDTH][MAP_HEIGHT];

char *destIp;
int destPort ;
int sendSd, reciveSd;
uint32_t nonceCl_to_Cl;

void setup(){
    for(int i=0; i<MAP_HEIGHT; i++){
        for (int j = 0; j < MAP_WIDTH; j++){
            map[j][i] = VOID;
        }
    }
    printf("\033[0;36m############################################ GAME START ############################################\033[0m\n");
}

void renderMap(){
    printf("\n");
    for(int i=0; i<=MAP_HEIGHT; i++){
        printf("\t\t\t\t       ");
        for (int j = 0; j < MAP_WIDTH; j++){
            if(i == MAP_HEIGHT){
                printf(" %d ", j);
                continue;
            }
            if(map[j][i] == VOID){
                printf(" . ");
            }else if(map[j][i] == PLAYER_LOCAL){
                printf("\033[0;36m");
                printf(" X ");
                printf("\033[0m");
            }else{
                printf("\033[0;31m");
                printf(" O ");
                printf("\033[0m");
            }
        }
        printf("\n\n");
    }
}

//Return FALSE if Column is full
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

int checkEndGame(){
    for(int i=0; i<MAP_WIDTH; i++){
        if(map[i][0] == VOID){ 
            return TRUE;
        }
    }
    printf("\033[1;33m"); 
    printf("PARITY\n");
    printf("\033[0m");
    return FALSE;
}










//Multiplayer part

void pack_match_move_message_local(struct message* aux, uint8_t column, int ptLen){
    aux->opcode = MATCH_MOVE_OPCODE;
    aux->my_id = sendSd;
    aux->addColumn = column;

    //encripted version
    aux->nonce = nonceCl_to_Cl;
}

struct sockaddr_in setupDestAddress(char *ip, int port){
    struct sockaddr_in other_addr;
    memset(&other_addr,0, sizeof(other_addr)); //pulizia
    other_addr.sin_family= AF_INET;
    other_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip , &other_addr.sin_addr);
    return other_addr;
}

int waitMove(){
    struct message m;
    struct sockaddr_in opponentAddr;

    recv_message(reciveSd, &m, (struct sockaddr*)&opponentAddr, TRUE, nonceCl_to_Cl);

    //Is the nonce correct ?
     //Nonce check
    printf("\nNonce rec: %d       stored:%d\n", m.nonce, nonceCl_to_Cl);
    if((nonceCl_to_Cl + 1) != m.nonce){
        printf("Errore: il nonce ricevuto non era quello aspettato\n");//Da stabilire con edo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        return 0;
    }
    nonceCl_to_Cl += 1;

    return (unsigned int)m.addColumn;
}

void sendMove(uint8_t column){
    struct sockaddr_in opponentAddr = setupDestAddress(destIp, destPort);
    struct message m;
    
    printf("invio nonceCl_to_Cl %d", nonceCl_to_Cl);
    nonceCl_to_Cl++;
    pack_match_move_message_local(&m, column, 5);
    send_message(&m, &opponentAddr, sendSd, TRUE);
    
}


int update(int first){
    int  winPlayer, win;
    int check = FALSE;
    unsigned int command, hostCommand;
    /***************
    //LOCAL PLAYER//
    ***************/
    if(first == TRUE){
        while(check == FALSE){ 
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
                printf("The Column %d is full, try an other one\n", command);
                printf("\033[0m"); 
                continue;
            }
        }

        sendMove((uint8_t)command);

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
        if(command == 9)
            return FALSE;

        renderMap();
    }
    

    /***************
    //HOST PLAYER //
    ***************/

    printf("Waiting for other player move...\n");
    hostCommand = waitMove();
    addDisk(hostCommand, PLAYER_HOST);

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

    return checkEndGame();
}










void forza4Engine(char *_destIp, int _destPort , int _sendSd, int _reciveSd, int first, int nonceCtoc){
    int goOn = TRUE;
    destIp = _destIp;
    destPort = _destPort;
    sendSd = _sendSd;
    reciveSd = _reciveSd;
    nonceCl_to_Cl = nonceCtoc;

    int firstTurn = first;
    //printf("\n%s\n", destIp);
    setup();
    while(goOn == TRUE){
        renderMap();
        goOn = update(firstTurn);
        firstTurn = TRUE;
    }
    renderMap();
}