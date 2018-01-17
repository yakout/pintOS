#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../lib/debug.h"

static void syscall_handler (struct intr_frame *);
static void exec_handler(struct intr_frame *f);
static void remove_handler(struct intr_frame *f);
static void read_handler(struct intr_frame *f);
static void tell_handler(struct intr_frame *f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{


 int *p = f->esp;
 if(*p == SYS_WRITE){
 	printf("%s\n",*(p+2));
  }

  thread_exit ();
}

static void
exec_handler(struct intr_frame *f){

}

static void
remove_handler(struct intr_frame *f){

}

static void
read_handler(struct intr_frame *f){

}

static void
tell_handler(struct intr_frame *f){

}
