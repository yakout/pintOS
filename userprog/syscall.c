#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/filesys.h"

struct lock *exec_lock;

static void syscall_handler (struct intr_frame *);
static void exec_handler(struct intr_frame *f);
static void remove_handler(struct intr_frame *f);
static void read_handler(struct intr_frame *f);
static void tell_handler(struct intr_frame *f);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static uint32_t get_parameter(struct intr_frame *f , int number);
static bool valid_string_pointer(char* str);
static bool valid_string(const char* str);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(exec_lock);
  index = 2;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{


 int p = get_parameter(f,PARM_ZERO);

 switch(p){
 	case SYS_EXEC:
 		exec_handler(f);
 		break;
 	case SYS_REMOVE:
 		remove_handler(f);
 		break;
 	case SYS_READ:
 		read_handler(f);
 		break;
 	case SYS_TELL:
 		tell_handler(f);
 		break;
 }

  thread_exit ();
}

static void
exec_handler(struct intr_frame *f){

	
	// get parameter
	const char* command_line = (char*)get_parameter(f,PARM_ONE);
	
	// check the pointer to be in user memory
	if(!valid_string(command_line)){
		f->eax = -1;
		return;
	}

 	// no interrupts until parent finishes
	lock_acquire (exec_lock);					
	
	// apply spwaning 
	tid_t pid = process_execute (command_line);
	
	// you can continue on
	lock_release(exec_lock);
	
	// return id
	f->eax = pid;
}
static void
open_handler(struct intr_frame *f){
	
	const char* file_name = (char*) get_parameter(f,PARM_ONE);
	if(!valid_string(file_name)){
		f->eax = -1;
		return;	
	}
	struct file* open_file = filesys_open (file_name);
	if(open_file == NULL){
		f->eax = -1;
		return;
	}
	struct file_entry* entry = malloc(sizeof(*entry));
	entry->fd = allocate_fd();
	entry->file = open_file;
	list_push_back(&thread_current()->open_file_table,&entry->hock);
	f->eax = entry->fd;
}

static void
remove_handler(struct intr_frame *f){
	// get file name
	const char* file_name = (char*)get_parameter(f,PARM_ONE);
	
	// check for validity.
	if(!valid_string(file_name)){
		f->eax = false;
		return;
	}
	// remove it
	f->eax =  filesys_remove(file_name);
}

static void
read_handler(struct intr_frame *f){
	const char* file_name = (char*) get_parameter(f,PARM_ONE);

}

static int
allocate_fd(){
	thread_current()->current_fd++;
  	return thread_current()->current_fd ;
}

static void
tell_handler(struct intr_frame *f){
	int fd = (int) get_parameter(f,PARM_ONE);
}

static bool
valid_string(const char* str){

	if(is_kernel_vaddr(str)){
		return false;
	}
	if(!valid_string_pointer(str)){
		return false;
	}
	return true;
}

static uint32_t
get_parameter(struct intr_frame *f , int number){
	int *p = f->esp;
	return *(p+number);
}


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static bool
valid_string_pointer(char* str){
	while(get_user((uint8_t*)str) != -1 && *str!='\0'){
		str++;
	}
	return *str=='\0';
}