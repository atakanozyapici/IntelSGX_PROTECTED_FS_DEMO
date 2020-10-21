#include <stdio.h>
#include <string.h>
#include <assert.h>
# include <unistd.h>
# include <pwd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <stdlib.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_tprotected_fs.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "app.h"
#include "enclave_u.h"
#define MAX_BUF_LEN 100
/*Size definitions */
#define MB_8 134217728
#define KB_16 16384
#define KB_4 4096
#define KB_64 65536
#define KB_1024 1048576
#define M_K_128 131072
/* Global EID shared by multiple threads */
sgx_enclave_id_t eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;


/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);

        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

//void ocall_dimatcopy(const char ordering, const char trans, size_t rows, size_t cols, const double alpha, double * AB, size_t lda, size_t ldb, size_t size)
//{
//    mkl_dimatcopy(ordering, trans, rows, cols, alpha, AB, lda, ldb);
//}

void ocall_print_uint(uint8_t * u, size_t size)
{
    printf("Info: uint8_t*: ");
    for(int i=0; i<size; i++)
    {   if(i%24==0)
            printf("\n");
        printf("%4d",(uint8_t) *(u+i));
    }
    printf("\n");
}

void* ocall_fopen(const char* filename, const char* mode){
  FILE* fp;
  fp = fopen(filename, mode);
  return fp;
}

int32_t ocall_fclose(void* fp){
  return fclose(fp);
}
size_t ocall_fwrite(char* data, size_t size, size_t rec_len, void* fp){
  return fwrite(data, size, rec_len, (FILE*)fp);
}
size_t ocall_fread(char* data, size_t size, size_t rec_len, void* fp){
  return fread(data, size, rec_len, (FILE*)fp);
}

//function to calculate the elapsed time since the given time
double elapsed_time_to_speed(struct rusage* begin, struct rusage* end, size_t size)
{
  int sec = ((end->ru_utime.tv_sec - begin->ru_utime.tv_sec) + (end->ru_stime.tv_sec - begin->ru_stime.tv_sec))  * 1000000;
  int usec = ((end->ru_utime.tv_usec - begin->ru_utime.tv_usec) + (end->ru_stime.tv_usec - begin->ru_stime.tv_usec));

  double speed = (double)((size* 1000000.0)/1024.0)  / (double)(sec + usec);
  return speed;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	uint64_t file_size = 0;
	SGX_FILE* fp;
	const char* filename = "SGX_File_Protection_System_bench.txt";
	const char* mode = "w+";
  const char* mode_read = "r+";

  int32_t fileHandle;
  size_t write_ret;
  char value[KB_1024];
  char data_out[KB_1024];
  struct rusage begin;
  struct rusage end;
  long time;
  double speed =0.0;
  double read_speed = 0, write_speed = 0;
  int return_size;
  size_t read_ret;

  for(int i = 0; i < KB_1024; i++){
    value[i] = (char)rand();
  }

  printf("size      reclen      sgx_fwrite                   sgx_fread\n");

  for(size_t size = KB_64; size <= KB_1024; size = size*2){
    for(int i = KB_4; i <= size; i = i*2){
      read_speed = 0;
      write_speed = 0;
      for(int round = 0; round < 10; round++){
        ret = ecall_file_open(eid, &fp, filename, mode);
        //time the write operation
        getrusage(RUSAGE_SELF, &begin);
        ecall_seq_file_write(eid, &write_ret, fp, size, i, value);
        getrusage(RUSAGE_SELF, &end);
        // printf("%d\n",write_ret);
        write_speed += elapsed_time_to_speed(&begin, &end, size);
        ret = ecall_file_get_file_size(eid, &return_size, fp);

        ret = ecall_file_flush_close(eid, &fileHandle, fp);

        ret = ecall_file_open(eid, &fp, filename, mode_read);
        getrusage(RUSAGE_SELF, &begin);
        ecall_seq_file_read(eid, &read_ret, fp, data_out, size,i);
        getrusage(RUSAGE_SELF, &end);

        read_speed += elapsed_time_to_speed(&begin, &end, size);

        //remove the file for the next run
        ret = ecall_file_close(eid, &fileHandle, fp);
        ret = ecall_file_remove(eid, &fileHandle, filename);
      }
      printf("%dkB      %dkB        %lf kB/sec        %lf kB/sec\n",size/1024, i/1024, write_speed/10,read_speed/10);
    }
  }

  printf("size      reclen      fwrite                      fread\n");

  for(size_t size = KB_64; size <= KB_1024; size = size*2){
    for(int i = KB_4; i <= size; i = i*2){
      read_speed = 0;
      write_speed = 0;
      for(int round = 0; round < 10; round++){
        FILE* fp = fopen(filename, mode);
        //time the write operation
        getrusage(RUSAGE_SELF, &begin);
        ecall_seq_file_write_none_sgx(eid, &write_ret, fp, size, i, value);
        getrusage(RUSAGE_SELF, &end);
        write_speed += elapsed_time_to_speed(&begin, &end, size);


        fflush(fp);
        fclose(fp);

        fp = fopen(filename, mode_read);
        getrusage(RUSAGE_SELF, &begin);
        ecall_seq_file_read_none_sgx(eid, &read_ret, fp, data_out, size,i);
        getrusage(RUSAGE_SELF, &end);

        read_speed += elapsed_time_to_speed(&begin, &end, size);

        //remove the file for the next run
        fclose(fp);
        remove(filename);
      }
      printf("%dkB      %dkB        %lf kB/sec        %lf kB/sec\n",size/1024, i/1024, write_speed/10,read_speed/10);
    }
  }

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}
