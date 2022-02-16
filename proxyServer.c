//
// Created by Amit cohen, id 315147330 on 08/12/2021.
//

/** Libraries **/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "threadpool.h"

/** Define **/
#define IP 0
#define HOST 1
#define MAX_SIZE_of_buffer 10000
#define filesystem 55
#define origin_server 66
/** Structs **/
typedef struct Node{
    char * address;
    int mask;
    int subnet_address[4];
    struct Node * next;
} Node;
typedef struct filter_list{
    Node * ip_head;
    Node * host_head;
}filter_list;
typedef struct HTTP_request {
    char * http_versions;
    char * method;
    char * file_path;
    char * host;
    char *host_by_ip;
    char * full_path;
    char * ip_address;
    int port;
}HTTP_request;
struct stat st = {0};

/** Private Functions **/
filter_list * build_filter_list(char * path);
void destroy_filter_list();
void create_new_node(char * buffer,int flag);
int parss_IP(char *buffer);
void init_the_ip(Node *pNode, char *buffer);
int convert_binary_to_Dec(char * bin_num);
char * create_binary_number(int offset);
int power(int a, int b);
int check_address_in_fireWall(char* address);
int check_host_in_fireWall(char* host);
int check_protocol(char * http_ver);
char *error_by_code(char * code);
char *get_massage_by_code(int number);
HTTP_request * request_parsing(char * request);
int finding_amount_of_characters(const char * string, char character);
void destroy_HTTP_struct(HTTP_request *HTTP_struct);
int check_alloc(const char *massage);
char *get_error(int number);
int check_HTTP_request(char * request);
int client_side_function(void* socket);
void create_the_path_in_filesystem(HTTP_request * req);
int connect_to_server(HTTP_request * request);
void proxy_main_function(char * filter_path,int max_request,int port,int pool_size);
int server_side_function(HTTP_request *pRequest, int fd);
char *get_mime_type(char *name);
char * get_ip_by_host(char * host);
char * get_host_by_ip(char * ip);
void write_error_to_fd(char * code,int fd);
void stream_the_file_to_client(char *file_path, int client_fd, int position, long total, char *file, HTTP_request *req);
int get_index_of_third_slash(const char * url);
char * build_the_request(HTTP_request* req);
char * allocation_string(int size);
filter_list * list;

int main(int argc,char * argv[]) {
    if(argc!=5){
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(EXIT_FAILURE);
    }
    char *ptr;
    int port=(int)strtol(argv[1], &ptr, 10);
    int num_threads_in_pool=(int)strtol(argv[2], &ptr, 10);
    int max_request=(int)strtol(argv[3], &ptr, 10);
    char * filter_path= allocation_string((int) strlen(argv[4]));
    if(!filter_path){
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    strcpy(filter_path,argv[4]);
    if(port<0||num_threads_in_pool<0||max_request<0){
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        free(filter_path);
        exit(EXIT_FAILURE);
    }
    proxy_main_function(filter_path,max_request,port,num_threads_in_pool);
    free(filter_path);
    exit(EXIT_SUCCESS);
}
/**
 *The function gets a path to the filter file and returns a two-headed linked list.
 *One head all IP addresses, second head all host addresses.
 * @return A two-headed linked list.
 */
filter_list * build_filter_list(char * path) {
    list = (filter_list *) malloc(sizeof(filter_list));
    list->host_head = NULL,list->ip_head = NULL;
    FILE *fd = fopen(path, "r");
    if (fd == NULL) {
        perror("error: fopen");
        exit(EXIT_FAILURE);
    }
    char buffer[50];
    while (fgets(buffer, 50, fd)>0) {
        if (buffer[strlen(buffer) - 2] == '\r' && buffer[strlen(buffer) - 1] == '\n')
            buffer[strlen(buffer) - 2] = '\0';
        else if (buffer[strlen(buffer) - 1] == '\n' || buffer[strlen(buffer) - 1] == '\r')
            buffer[strlen(buffer) - 1] = '\0';
        if (isalpha(buffer[0]))
            create_new_node( buffer, HOST);
        else
            create_new_node( buffer, IP);
        memset(buffer,'\0',50);
    }
    fclose(fd);
    return list;
}
/**
 *The function frees all the members of the list and deletes the list.
 */
void destroy_filter_list(){
    Node *current = NULL, *next = NULL;
    current = list->ip_head;
    while (current != NULL) {
        next = current->next;
        free(current->address);
        free(current);
        current = next;
    }
    current=NULL,next=NULL;
    current = list->host_head;
    while (current != NULL) {
        next = current->next;
        free(current->address);
        free(current);
        current = next;
    }
    free(list);
    list= NULL;
}
/**
 *The function generates a new NODE and inserts it into the list.
 * @param buffer the address
 * @param flagIf it's an IP address, the flag is equal to 0, if it's a host address, the flag is equal to 1.
 */
void create_new_node(char * buffer,int flag) {
    Node *newNode = (Node *) malloc(sizeof(Node));
    newNode->address = allocation_string((int) strlen(buffer));
    if(!newNode->address){
        perror("malloc");
        destroy_filter_list();
        exit(EXIT_FAILURE);
    }
    strcpy(newNode->address, buffer);
    if (flag == IP)/*ip*/ {
            newNode->mask = parss_IP(buffer);
            init_the_ip(newNode, buffer);
            newNode->next = list->ip_head;
            list->ip_head = newNode;
    } else/*host*/{
            newNode->next = list->host_head;
            list->host_head = newNode;
    }
}
/**
 *The function changes the IP address according to the requested subnet.
 * @param pNode the new node
 * @param buffer the address
 */
void init_the_ip(Node *pNode, char *buffer) {
    char* buffer2= allocation_string((int)strlen(buffer));
    if(!buffer2){
        destroy_filter_list();
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    strcpy(buffer2,buffer);
    char *ptr = strtok(buffer2, "."),*ptr2;
    int i = 0;
    while (ptr) {
        pNode->subnet_address[i]=(int)strtol(ptr, &ptr2, 10);
        i++;
        ptr= strtok(NULL,".");
    }
    int offset=pNode->mask/8,offset_bit=pNode->mask%8,and;
    if(offset_bit>0) {
        char *ptr3 = create_binary_number(offset_bit);
        and = convert_binary_to_Dec(ptr3);
        pNode->subnet_address[offset] = pNode->subnet_address[offset] & and;
        for(int j=offset+1;j<4;j++)
            pNode->subnet_address[j]=0;
        free(ptr3);
    }
    else if(offset<4){
        for(int j=offset;j<4;j++)
            pNode->subnet_address[j]=0;
    }
    free(buffer2);
}
/**
 * the function return the subnet of thr address
 * @param buffer the address
 * @return subnet
 */
int parss_IP(char *buffer) {
    char * ptr,*ptr2;
    int mask=32;
    ptr=strchr(buffer,'/');
    if(ptr){
        mask=(int)strtol(&ptr[1],&ptr2,10);
        buffer[strlen(buffer)- strlen(ptr)]='\0';
        return mask;
    }
    return mask;
}
/**
 *The function takes a binary string and returns its value in decimal numbers
 * @param bin_num the binary string
 * @return the number in decimal
 */
int convert_binary_to_Dec(char * bin_num){
    int dec=0,index=0;
    for (int i = (int) strlen(bin_num) - 1; i >= 0; i--, index++)
        if (bin_num[i] == '1')
            dec += power(2, index);
    return dec;
}
/**
 *The function performs a powerful operation.
 * @param a the number
 * @param b To the power of B
 * @return The result
 */
int power(int a, int b) {
    int res=1;
    for(int i=0;i<b;i++){
        res*=a;
    }
    return res;
}
/**
 * The function takes the number n and returns a binary string of length 8, with the n digits left 1, and the rest 0.
 * @param offset the number
 * @return binary string
 */
char * create_binary_number(int offset){
    char* number= allocation_string(8);
    if(!number){
        perror("malloc");
        destroy_filter_list();
        exit(EXIT_FAILURE);
    }
    for(int i=0;i<8;i++)
        if(i<offset)
            number[i]='1';
        else
            number[i]='0';
    return number;
}
/**
 *The function checks if the IP address appears in the filter file
 * @param address the IP to check
 * @return Returns 0 if found, otherwise 1.
 */
int check_address_in_fireWall(char* address) {
    int ip[4];
    if (!address)
        return 1;
    char *address2 = allocation_string(15);
    if(!address2)
        return -1;
    strcpy(address2, address);
    char *ptr = strtok(address2, "."), *ptr2;
    ip[0] = (int) strtol(ptr, &ptr2, 10);
    int i = 1;
    while (ptr != NULL && i < 4) {
        ptr = strtok(NULL, ".");
        ip[i] = (int) strtol(ptr, &ptr2, 10);
        i++;
    }
    if (list != NULL) {
        if (list->ip_head != NULL) {
            Node *pointer = list->ip_head;
            while (pointer != NULL) {
                if (pointer->subnet_address[0] == (pointer->subnet_address[0] & ip[0]) &&
                    pointer->subnet_address[1] == (pointer->subnet_address[1] & ip[1]) &&
                    pointer->subnet_address[2] == (pointer->subnet_address[2] & ip[2]) &&
                    pointer->subnet_address[3] == (pointer->subnet_address[3] & ip[3])) {
                    free(address2);
                    return 0;
                }
                pointer = pointer->next;
            }
        }
    }
    free(address2);
    return 1;
}
/**
 *
 * @param list of filter
 * @param host the address to check
 * @return 0 if the host in the filter file
 */
int check_host_in_fireWall(char* host){
    if(list!=NULL) {
        Node *ptr = list->host_head;
        while (ptr != NULL) {
            if (strcmp(host, ptr->address) == 0)
                return 0;
            ptr = ptr->next;
        }
    }
    return 1;
}
/**
 * The function checks the version of the HTTP request, whether it is 1.1 or 1.0
 * @param http_ver the version to check
 * @return Returns 1 if correct, 0 otherwise
 */
int check_protocol(char * http_ver) {
    if (strcmp(http_ver, "HTTP/1.0") == 0 || strcmp(http_ver, "HTTP/1.1") == 0)
        return 1;
    return 0;
}
/**
 *The function returns headers of the requested error
 * @param code the code error
 */
char * error_by_code(char * code){
    char* ptr2;
    int code_number =(int)strtol(code,&ptr2,10);
    char buffer_message[MAX_SIZE_of_buffer+100];
    char buffer_HTML[MAX_SIZE_of_buffer];
    char * mes= get_error(code_number),*body_mes= get_massage_by_code(code_number);
    int size2= sprintf(buffer_HTML,"<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\r\n<BODY><H4>%d %s</H4>\r\n%s\r\n</BODY></HTML>\r\n",code_number,mes,code_number,mes,body_mes);
    int size= sprintf(buffer_message,"HTTP/1.0 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",code_number,mes,size2,buffer_HTML);
    char * message= allocation_string(size);
    if(!message){
        free(mes);
        free(body_mes);
        return NULL;
    }
    strcpy(message,buffer_message);
    free(mes);
    free(body_mes);
    return message;
}
/**
 *The function returns the error according to the error code
 * @param number the code error
 * @return error
 */
char *get_massage_by_code(int number) {
    char * massage= allocation_string(1);
    if(!massage)
        return NULL;
    switch (number) {
        case 400: {
            massage = realloc(massage, sizeof(char) * strlen("Bad Request.") + 1);
            check_alloc(massage);
            strcpy(massage, "Bad Request.");
            break;
        }
        case 403: {
            massage = realloc(massage, sizeof(char) * strlen("Access denied.") + 1);
            check_alloc(massage);
            strcpy(massage, "Access denied.");
            break;
        }
        case 404: {
            massage = realloc(massage, sizeof(char) * strlen("File not found.") + 1);
            check_alloc(massage);
            strcpy(massage, "File not found.");
            break;
        }
        case 500: {
            massage = realloc(massage, sizeof(char) * strlen("Some server side error.") + 1);
            check_alloc(massage);
            strcpy(massage, "Some server side error.");
            break;
        }
        case 501: {
            massage = realloc(massage, sizeof(char) * strlen("Method is not supported.") + 1);
            check_alloc(massage);
            strcpy(massage, "Method is not supported.");
            break;
        }
        default:
            break;
    }
    return massage;
}
/**
 *The function returns the error according to the error code
 * @param number the code error
 * @return error
 */
char *get_error(int number) {
    char * massage=(allocation_string(1));
    if(!massage)
        return NULL;
    switch (number) {
        case 400: {
            massage = realloc(massage, sizeof(char) * strlen("Bad Request") + 1);
            check_alloc(massage);
            strcpy(massage, "Bad Request");
            break;
        }
        case 403: {
            massage = realloc(massage, sizeof(char) * strlen("Forbidden") + 1);
            check_alloc(massage);
            strcpy(massage, "Forbidden");
            break;
        }
        case 404: {
            massage = realloc(massage, sizeof(char) * strlen("Not Found") + 1);
            check_alloc(massage);
            strcpy(massage, "Not Found");
            break;
        }
        case 500: {
            massage = realloc(massage, sizeof(char) * strlen("Internal Server Error") + 1);
            check_alloc(massage);
            strcpy(massage, "Internal Server Error");
            break;
        }
        case 501: {
            massage = realloc(massage, sizeof(char) * strlen("Not supported") + 1);
            check_alloc(massage);
            strcpy(massage, "Not supported");
            break;
        }
        default:
            break;
    }
    return massage;
}
/**
 * The function checks if the memory allocation is correct
 * @param massage the string to check
 * @return 1 If correct, otherwise 0
 */
int check_alloc(const char *massage) {
    if (massage == NULL) {
        perror("alloc");
        return -1;
    }
    return 1;
}
/**
 *The function builds the structure according to the request, host, IP, version, path, method
 * @param request the string
 * @return the struct
 */
HTTP_request * request_parsing(char * request) {
    HTTP_request *req = (HTTP_request *) malloc(sizeof(HTTP_request));
    req->host = NULL;
    req->file_path = NULL;
    req->full_path = NULL;
    req->method = NULL;
    req->http_versions = NULL;
    req->ip_address=NULL;
    req->host_by_ip=NULL;
    char *copy_request = allocation_string((int) strlen(request)),*pointer1,*pointer2,*pointer3;
    if(!copy_request)
        return NULL;
    strcpy(copy_request, request);
    pointer1=strtok(copy_request," ");
    req->method= allocation_string((int) strlen(pointer1));
    if(!req->method) {
        free(copy_request);
        return NULL;
    }
    strcpy(req->method,pointer1);
    pointer1=strtok(NULL," ");
    pointer2=strstr(pointer1,"http://");
    int index;
    if(pointer2){
        index=get_index_of_third_slash(pointer2);
        if(index!=-1&&pointer2[index+1]!='\0'){
            req->file_path= allocation_string((int)strlen(&pointer1[index]));
            if(!req->file_path) {
                free(copy_request);
                return NULL;
            }
            strcpy(req->file_path,&pointer1[index]);
        } else{
            req->file_path= allocation_string(11);
            if(!req->file_path){
                free(copy_request);
                return NULL;
            }
            strcpy(req->file_path,"/index.html");
        }
    }else{
        pointer3=strstr(pointer1,"/");
        if(pointer3&&pointer3[1]!=' '){
            req->file_path= allocation_string((int)strlen(pointer3));
            if(!req->file_path){
                free(copy_request);
                return NULL;
            }
            strcpy(req->file_path,pointer3);
        }
        else{
            req->file_path= allocation_string(11);
            if(!req->file_path){
                free(copy_request);
                return NULL;
            }
            strcpy(req->file_path,"/index.html");
        }
    }
    strcpy(copy_request, request);
    pointer1= strstr(copy_request,"HOST");
    if(!pointer1){
        pointer1= strstr(copy_request,"Host");
        if(!pointer1){
            pointer1= strstr(copy_request,"host");
        }
    }
    pointer2=strtok(&pointer1[6],"\r\n");
    pointer3=strstr(pointer2,":");
    int size_to_copy = 0,size1_2= ((int) strlen(pointer2));
    if(pointer3!=NULL) {
        size_to_copy = ((int) strlen(pointer2)) - ((int) strlen(pointer3));
    }
    else
        size_to_copy=size1_2;
    req->host= allocation_string(size_to_copy);
    if(!req->host){
        free(copy_request);
        return NULL;
    }
    strncpy(req->host,&pointer1[6],size_to_copy);
    if(isdigit(req->host[0])){
        req->ip_address= allocation_string((int) strlen(req->host));
        if(!req->ip_address){
            free(copy_request);
            return NULL;
        }
        strcpy(req->ip_address,req->host);
        char * host= get_host_by_ip( req->ip_address);
        if(!host)
            return NULL;
        req->host_by_ip= allocation_string((int) strlen(host));
        if(!req->host_by_ip){
            free(copy_request);
            return NULL;
        }
        strcpy(req->host_by_ip, host);
        free(host);
    }
    else{
        char * ip= get_ip_by_host(req->host);
        if(ip) {
            req->ip_address = allocation_string((int) strlen(ip));
            if(!req->ip_address){
                free(copy_request);
                return NULL;
            }
            strcpy(req->ip_address, ip);
        }
    }
    pointer1=strstr(copy_request,"HTTP");
    pointer2=strstr(pointer1,"\r\n");
    req->http_versions= allocation_string((int) strlen(pointer1)-(int) strlen(pointer2));
    if(!req->http_versions){
        free(copy_request);
        return NULL;
    }
    strncpy(req->http_versions,pointer1,(int) strlen(pointer1)-(int) strlen(pointer2));
    req->full_path= allocation_string((int) strlen(req->file_path)+(int) strlen(req->host));
    if(!req->full_path){
        free(copy_request);
        return NULL;
    }
    strcpy(req->full_path,req->host);
    strcat(req->full_path,req->file_path);
    req->port=80;
    free(copy_request);
    return req;
}
/**
 *This function counts the number of occurrences of a particular character within a string.
 * @param string The string for testing
 * @param character The requested character
 * @return The number of times the character appears.
 */
int finding_amount_of_characters(const char * string, char character) {
    int counter = 0;
    for (int i = 0; string[i] != '\0'; i++)
        if (string[i] == character)
            counter++;
    return counter;
}
/**
 *The function, breaks down the structure, and frees up all memory
 * @param HTTP_struct The structure is erasable.
 */
void destroy_HTTP_struct(HTTP_request *HTTP_struct){
    free(HTTP_struct->host);
    free(HTTP_struct->file_path);
    free(HTTP_struct->full_path);
    free(HTTP_struct->http_versions);
    free(HTTP_struct->method);
    free(HTTP_struct->ip_address);
    free(HTTP_struct->host_by_ip);
    free(HTTP_struct);
    HTTP_struct=NULL;
}
/**
 * The function checks the correctness of the request
 * @param request the  string to check
 * @return 1 If the request is valid, 0 otherwise
 */
int check_HTTP_request(char * request) {
    char *copy_request = allocation_string((int)strlen(request));
    char *first_line = allocation_string(1);
    if(!first_line||!copy_request)
        return -1;
    strcpy(copy_request, request);
    char *ptr = strstr(copy_request, "\r\n");
    first_line = realloc(first_line, strlen(copy_request) - strlen(ptr) + 1);
    check_alloc(first_line);
    memset(first_line, '\0', strlen(copy_request) - strlen(ptr) + 1);
    strncpy(first_line, copy_request, strlen(copy_request) - strlen(ptr));
    strcpy(copy_request, request);
    if (finding_amount_of_characters(first_line, ' ') != 2) {
        free(copy_request);
        free(first_line);
        return 0;
    }
    ptr = strstr(first_line, "HTTP");
    if (ptr == NULL) {
        free(copy_request);
        free(first_line);
        return 0;
    }

    if (!check_protocol(ptr)) {
        free(copy_request);
        free(first_line);
        return 0;
    }
    ptr = strstr(copy_request, "HOST:");
    if (ptr == NULL) {
        ptr = strstr(copy_request, "Host:");
        if (ptr == NULL) {
            ptr = strstr(copy_request, "host:");
            if (ptr == NULL) {
                free(copy_request);
                free(first_line);
                return 0;
            }
        }
    }
    free(copy_request);
    free(first_line);
    return 1;
}
/**
 *The function handles every request from the client.
 * @param socket the socket fd of client
 */
int client_side_function(void* socket) {
    int socket_fd_client = *(int *) socket, status;
    unsigned char *buffer =(unsigned char *) malloc(sizeof (unsigned char *)*MAX_SIZE_of_buffer+1);
    memset(buffer,0,sizeof (unsigned char *)*MAX_SIZE_of_buffer);
    read(socket_fd_client, buffer, MAX_SIZE_of_buffer);
    HTTP_request *request;
    if (strlen((char*)buffer)>0&&check_HTTP_request((char*)buffer)) {
        request = request_parsing((char *) buffer);
        if(!request){
            close(socket_fd_client);
            free(buffer);
            return -1;
        }
    }
    else {
        write_error_to_fd("400", socket_fd_client);
        close(socket_fd_client);
        free(buffer);
        return -1;
    }
    char *rr= build_the_request(request);
    if(!rr){
        write_error_to_fd("404", socket_fd_client);
        destroy_HTTP_struct(request);
        close(socket_fd_client);
        free(buffer);
        free(rr);
        return -1;
    }
    printf("HTTP request =\r\n%s\r\nLEN = %d\r\n", rr, (int) strlen((char*)rr));
    if (strcmp(request->method, "GET") != 0) {
        write_error_to_fd("501", socket_fd_client);
        destroy_HTTP_struct(request);
        close(socket_fd_client);
        free(rr);
        free(buffer);
        return -1;
    }
    if (request->ip_address&& strcmp(request->ip_address,"error")!=0) {
        if (check_address_in_fireWall(request->ip_address) ==0|| check_host_in_fireWall(request->host)==0) {
            write_error_to_fd("403", socket_fd_client);
            destroy_HTTP_struct(request);
            close(socket_fd_client);
            free(buffer);
            free(rr);
            return -1;
        }
        if (check_address_in_fireWall(request->ip_address) ==-1|| check_host_in_fireWall(request->host)==-1){
            write_error_to_fd("404", socket_fd_client);
            destroy_HTTP_struct(request);
            close(socket_fd_client);
            free(buffer);
            free(rr);
            return -1;
        }
    }
    else{
        write_error_to_fd("404", socket_fd_client);
        destroy_HTTP_struct(request);
        close(socket_fd_client);
        free(buffer);
        free(rr);
        return -1;
    }
    if (stat(request->full_path, &st) == -1) {
        status = server_side_function(request, socket_fd_client);
        if (status == -1) {
            write_error_to_fd("500", socket_fd_client);
            destroy_HTTP_struct(request);
            free(buffer);
            close(socket_fd_client);
            free(rr);
            return -1;
        }
        printf("File is given from origin server\r\n");

    } else {
        char * rrr= build_the_request(request);
        if(!rrr){
            write_error_to_fd("404", socket_fd_client);
            destroy_HTTP_struct(request);
            close(socket_fd_client);
            free(buffer);
            free(rr);
            return -1;
        }
        stream_the_file_to_client(request->full_path, socket_fd_client, filesystem, 0, request->file_path, request);
        printf("File is given from local filesystem\r\n");
        free(rrr);
    }
    close(socket_fd_client);
    free(buffer);
    free(rr);
    destroy_HTTP_struct(request);
    return 1;
}
/**
 * The function opens a request in front of the server, and rhymes the requested page to the client
 * @param pRequest
 * @param fd
 * @return
 */
int server_side_function(HTTP_request *pRequest, int fd) {
    char *request = build_the_request(pRequest);
    if(!request)
        return -1;
    int socket_fd = connect_to_server(pRequest), check, flag = 0, flag_200_OK = 0;
    char a[100];
    memset(a, '\0', 100);
    if (socket_fd == -1)
        return -1;
    long counter = 0;
    unsigned char *buffer = (unsigned char *) malloc(MAX_SIZE_of_buffer * (sizeof(unsigned char)) + 1);
    if (buffer == NULL) {
        perror("malloc  ");
        return -1;
    }
    memset(buffer, 0, MAX_SIZE_of_buffer);
    int size_to_write = (int) strlen(request);
    if ((write(socket_fd, request, size_to_write)) < 0) {
        perror("error: write");
        free(buffer);
        free(request);
        return -1;
    }
    free(request);
    FILE *file_d = NULL;
    char *ptr = NULL;

    while (1) {
        memset(buffer, 0, MAX_SIZE_of_buffer);
        if ((check = (int) read(socket_fd, buffer, MAX_SIZE_of_buffer - 1)) < 0) {
            perror("error: read");
            return -1;
        }
        counter += check;
        if (!check && flag_200_OK) {
            fclose(file_d);
            stream_the_file_to_client(pRequest->full_path, fd, origin_server, counter, pRequest->file_path, pRequest);
            break;
        }
        if (!flag_200_OK) {
            if (strstr((char *) buffer, "200 OK")) {
                create_the_path_in_filesystem(pRequest);
                file_d = fopen(pRequest->full_path, "w+");
                flag_200_OK = 1;
                if (file_d == NULL) {
                    perror("error: fopen");
                    free(buffer);
                    return -1;
                }
            }
            ptr = strstr((char *) buffer, "\r\n\r\n");
        }
        if (!ptr && flag_200_OK && !flag) {
            size_to_write = (int) strlen((char *) buffer);
            if (write(fd, buffer, size_to_write) < 0) {
                free(buffer);
                if (file_d)
                    fclose(file_d);
                return -1;
            }
            continue;
        }
        if (ptr && !flag && flag_200_OK) {
            size_to_write = (int) strlen((char *) buffer) - (int) strlen(ptr) + 4;
            if (fd > -1)
                if (write(fd, buffer, size_to_write) < 0) {
                    free(buffer);
                    if (file_d)
                        fclose(file_d);
                    return -1;
                }
            flag = 1;
            int i = 0, offset = 0;
            for (; i < MAX_SIZE_of_buffer; i++)
                if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n') {
                    offset = i + 4;
                    break;
                }
            if (file_d)
                if ((fwrite(&buffer[offset], sizeof(unsigned char), check - offset, file_d)) < 1) {
                    perror("error: fwrite");
                    free(buffer);
                    if (file_d)
                        fclose(file_d);
                    return -1;
                }
            continue;
        } else if (flag) {
            if (file_d)
                if ((fwrite(buffer, sizeof(unsigned char), check, file_d)) < 1) {
                    perror("error: fwrite");
                    if (file_d)
                        fclose(file_d);
                    free(buffer);
                    return -1;
                }
        } else {
            free(buffer);
            if (file_d)
                fclose(file_d);
            return 0;
        }
    }
    free(buffer);
    return 1;
}
/**
 * The function produces folders and the requested file.
 * @param url
 */
void create_the_path_in_filesystem(HTTP_request * req) {
    char *a = allocation_string((int) strlen(req->full_path));
    if (!a)
        return;
    strcpy(a, req->full_path);
    int amount = finding_amount_of_characters(a, '/');
    if (stat(req->host, &st) == -1) {
        mkdir(req->host, 0700);
    }
    FILE *fd;
    if (amount == 1) {
        fd = fopen(a, "w+");
        fclose(fd);
        free(a);
    } else {
        char *ptr = strtok(a, "/");
        int size=(int) strlen(ptr);
        char *dir_first = allocation_string(size);
        if (!dir_first)
            return;
        strcpy(dir_first, ptr);
        if (stat(dir_first, &st) == -1)
            mkdir(dir_first, 0700);

        while (amount > 1) {
            ptr = strtok(NULL, "/");
            size=(int) strlen(dir_first);
            dir_first = realloc(dir_first, sizeof(char) *(size + 2));
            check_alloc(dir_first);
            strcat(dir_first, "/");
            size=(int)strlen(dir_first)+(int)strlen(ptr);
            dir_first = realloc(dir_first, sizeof(char) * (size+ 1));
            check_alloc(dir_first);
            strcat(dir_first, ptr);
            if (stat(dir_first, &st) == -1)
                mkdir(dir_first, 0700);
            amount--;
        }
        size=(int) strlen(dir_first);
        dir_first = realloc(dir_first, sizeof(char) * (size + 2));
        check_alloc(dir_first);
        strcat(dir_first, "/");
        ptr = strtok(NULL, "/");
        if (ptr) {
            size=(int) strlen(dir_first)+(int) strlen(ptr);
            dir_first = realloc(dir_first, sizeof(char) * (size + 1));
        }
        check_alloc(dir_first);
        strcat(dir_first, ptr);
        fd = fopen(dir_first, "w+");
        fclose(fd);
        free(a);
        free(dir_first);
    }
}
/**
 *Socket connection
 * @param url
 * @return The socket file descriptor.
 */
int connect_to_server(HTTP_request * request) {
    struct sockaddr_in serv_address;
    struct hostent * server;
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("socket");
        return -1;
    }
    server = gethostbyname(request -> host);
    if (server == NULL) {
        herror("get host by name ");
        return -1;
    }
    serv_address.sin_family = AF_INET;
    bcopy((char * ) server -> h_addr_list[0], (char * ) & serv_address.sin_addr.s_addr, server -> h_length);
    serv_address.sin_port = htons(request -> port);
    if (connect(socket_fd, (const struct sockaddr * ) & serv_address, sizeof(serv_address)) < 0) {
        perror("connect");
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}
/**
 *
 * @param name
 * @return
 */
char *get_mime_type(char *name)
{
    char *ext = strrchr(name, '.');
    if (!ext) return NULL;
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".au") == 0) return "audio/basic";
    if (strcmp(ext, ".wav") == 0) return "audio/wav";
    if (strcmp(ext, ".avi") == 0) return "video/x-msvideo";
    if (strcmp(ext, ".mpeg") == 0 || strcmp(ext, ".mpg") == 0) return "video/mpeg";
    if (strcmp(ext, ".mp3") == 0) return "audio/mpeg";
    return NULL;
}
/**
 * The function receives a host string and returns an IP string
 * @param host
 * @return
 */
char * get_ip_by_host(char * host){
    struct hostent* server;
    struct in_addr** addr;
    server = gethostbyname(host);
    if (server == NULL) return NULL;
    addr = (struct in_addr**)server->h_addr_list;
    return inet_ntoa(*addr[0]);
}
/**
 * The function receives an IP string and returns a host string
 * @param ip
 * @return
 */
char * get_host_by_ip(char * ip){
    struct hostent *host;
    struct in_addr addr;
    inet_aton(ip,&addr);
    host= gethostbyaddr(&addr,sizeof (addr),AF_INET);
    if(host==NULL)
        return "error";
    char * host_name= allocation_string((int)strlen(host->h_name));
    if(!host_name)
        return NULL;
    strcpy(host_name,host->h_name);
    return host_name;
}
/**
 * The function writes the error into the client's socket
 * @param code
 */
void write_error_to_fd(char * code,int fd) {
    char *error = error_by_code(code);
    int size = (int) strlen(error);
    if (fd > -1)
        write(fd, error, size);
    free(error);
}
/**
 * The function writes the file into the client's socket
 * @param file_path
 * @param client_fd
 * @param position
 */
void stream_the_file_to_client(char *file_path, int client_fd, int position, long total, char *file, HTTP_request *req) {
    unsigned char * buffer = (unsigned char * ) malloc(MAX_SIZE_of_buffer * (sizeof(unsigned char)));
    if (buffer == NULL) {
        perror("malloc  ");
        return;
    }
    char bu[MAX_SIZE_of_buffer],bu1[MAX_SIZE_of_buffer];
    stat(file_path, & st);
    int size = (int) st.st_size, check,size_to_w;
    if(position==filesystem) {
        sprintf(bu, "%s 200 OK\r\n", req->http_versions);
        char type[20];
        if (get_mime_type(file) != NULL) {
            strcpy(type, get_mime_type(file));
            strcat(bu, "Content-type: ");
            strcat(bu, type);
        }
        sprintf(bu1, "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size);
        strcat(bu, bu1);
        size_to_w = (int) strlen(bu) + 1;
        if (client_fd > -1)
            write(client_fd, bu, size_to_w);
    }
    FILE * fd= fopen(file_path,"r");
    memset(buffer, 0, MAX_SIZE_of_buffer);
    int read_counter=0;
    while (1) {
        memset(buffer, 0, MAX_SIZE_of_buffer);
        read_counter = (int) fread(buffer, sizeof(unsigned char), MAX_SIZE_of_buffer - 1, fd);
        if (!read_counter)
            break;
        if (client_fd > -1)
            if (write(client_fd, buffer, read_counter) < 0) {
                fclose(fd);
                free(buffer);
                return;
            }
    }
    if(position==filesystem){
        total=size+(int) strlen(bu);
    }
    printf("\nTotal response bytes: %ld\n",total);
    fclose(fd);
    free(buffer);
}
/**
 *The function returns the index of the third appearance of the slash.
 * @param url
 * @return
 */
int get_index_of_third_slash(const char * url) {
    int counter = 0;
    for (int i = 0; url[i] != '\0'; i++)
        if (url[i] == '/') {
            counter++;
            if (counter == 3)
                return i;
        }
    return -1;
}
/**
 * The function generates the HTTP request according to the fixed format.
 * @param url
 * @return String of request.
 */
char * build_the_request(HTTP_request* req) {
    char buff[MAX_SIZE_of_buffer];
    int size= sprintf(buff,"%s %s %s\r\nHost: %s\r\nConnection: close\r\n\r\n",req->method,req -> file_path,req->http_versions,req->host);
    char * request = allocation_string(size+1);
    if(!request)
        return NULL;
    strcpy(request,buff);
    return request;
}
/**
 * The main function of the code, creates the pool of thread, and sends the requests.
 * @param filter_path
 * @param max_request
 * @param port
 * @param pool_size
 */
void proxy_main_function(char * filter_path,int max_request,int port,int pool_size){
    list = build_filter_list(filter_path);
    threadpool * pool= create_threadpool(pool_size);
    int  sockfd,newsockfd;
    char buffer[256];
    struct sockaddr_in serv_addr;
    struct  sockaddr cli_addr;
    socklen_t  clilen;
    int n,rc;
    sockfd =socket(AF_INET,SOCK_STREAM,0);
    if(sockfd<0) {
        perror("error: opening socket\n");
        destroy_filter_list();
        exit(EXIT_FAILURE);
    }
    serv_addr.sin_family =AF_INET;
    serv_addr.sin_addr.s_addr =INADDR_ANY;
    serv_addr.sin_port=htons(port);
    if(bind(sockfd,(struct  sockaddr*)&serv_addr,sizeof (serv_addr))<0) {
        perror("error: on binding\n");
        destroy_filter_list();
        destroy_threadpool(pool);
        free(filter_path);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    if(listen(sockfd,5)<0){
        perror("error: on listening\n");
        destroy_filter_list();
        destroy_threadpool(pool);
        free(filter_path);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    for(int i=0;i<max_request;i++) {
        newsockfd = accept(sockfd, NULL, NULL);
        if (newsockfd < 0)
            perror("error: on accept\n");
        dispatch(pool,client_side_function,&newsockfd);
    }
    close(sockfd);
    destroy_filter_list();
    destroy_threadpool(pool);
}
/**
 * The function returns a dynamically assigned string according to the desired size
 * @param size
 * @return
 */
char * allocation_string(int size){
    char * str=(char*) malloc(sizeof(char)*(size+1));
    if(check_alloc(str)==-1){
        return NULL;
    }
    memset(str,'\0',size+1);
    return str;
}