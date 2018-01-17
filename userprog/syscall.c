#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"

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


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(exec_lock);
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
	if(command_line >= PHYS_BASE){
		f->eax = -1;
		return;
	}
	if(!valid_string_pointer(command_line)){
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
remove_handler(struct intr_frame *f){
	// get file name
	// get the file
	// remove it
	// return true if yes else return no
}

static void
read_handler(struct intr_frame *f){

}

static void
tell_handler(struct intr_frame *f){

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